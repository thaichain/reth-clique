//! [Account keychain] precompile for managing session keys and spending limits.
//!
//! Each account can authorize secondary keys (session keys) with per-token spending caps,
//! signature type constraints, and expiry. The main key (address zero) retains full control;
//! T6 admin keys can also manage other access keys.
//!
//! [Account keychain]: <https://docs.tempo.xyz/protocol/transactions/AccountKeychain>

pub mod dispatch;

use std::collections::HashSet;

use alloy::sol_types::SolCall;
use tempo_contracts::precompiles::{AccountKeychainError, AccountKeychainEvent, ITIP20};
pub use tempo_contracts::precompiles::{
    IAccountKeychain,
    IAccountKeychain::{
        CallScope, KeyInfo, KeyRestrictions, SelectorRule, SignatureType, TokenLimit,
        burnKeyAuthorizationWitnessCall, getAllowedCallsCall, getKeyCall, getRemainingLimitCall,
        getRemainingLimitWithPeriodCall, getTransactionKeyCall,
        isKeyAuthorizationWitnessBurnedCall, removeAllowedCallsCall, revokeKeyCall,
        setAllowedCallsCall, updateSpendingLimitCall,
    },
    authorizeKeyCall, authorizeKeyWithWitnessCall, getAllowedCallsReturn, getRemainingLimitReturn,
};
use tempo_primitives::TempoAddressExt;

use crate::{
    ACCOUNT_KEYCHAIN_ADDRESS,
    error::Result,
    has_duplicates_metered,
    storage::{Handler, Mapping, Set},
    tip20_factory::TIP20Factory,
};
use alloy::primitives::{Address, B256, FixedBytes, TxKind, U256, keccak256};
use tempo_precompiles_macros::{Storable, contract};

/// Allowed TIP-20 selectors for recipient-constrained rules.
const TIP20_TRANSFER_SELECTOR: [u8; 4] = ITIP20::transferCall::SELECTOR;
const TIP20_APPROVE_SELECTOR: [u8; 4] = ITIP20::approveCall::SELECTOR;
const TIP20_TRANSFER_WITH_MEMO_SELECTOR: [u8; 4] = ITIP20::transferWithMemoCall::SELECTOR;

/// (T7+) Alias for zero remaining periodic spend, used to avoid clearing the storage slot.
const ZERO_PERIODIC_REMAINING_SENTINEL: U256 = U256::MAX;

#[inline]
pub fn is_constrained_tip20_selector(selector: [u8; 4]) -> bool {
    matches!(
        selector,
        TIP20_TRANSFER_SELECTOR | TIP20_APPROVE_SELECTOR | TIP20_TRANSFER_WITH_MEMO_SELECTOR
    )
}

/// Key information stored in the precompile
///
/// Storage layout (packed into single slot, right-aligned):
/// - byte 0: signature_type (u8)
/// - bytes 1-8: expiry (u64, little-endian)
/// - byte 9: enforce_limits (bool)
/// - byte 10: is_revoked (bool)
/// - byte 11: is_admin (bool)
#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
pub struct AuthorizedKey {
    /// Signature type used by this key.
    pub signature_type: StoredSignatureType,
    /// Block timestamp when key expires
    pub expiry: u64,
    /// Whether to enforce spending limits for this key
    pub enforce_limits: bool,
    /// Whether this key has been revoked. Once revoked, a key cannot be re-authorized
    /// with the same key_id. This prevents replay attacks.
    pub is_revoked: bool,
    /// Whether this key has admin privileges for keychain management.
    pub is_admin: bool,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub enum StoredSignatureType {
    #[default]
    Secp256k1,
    P256,
    WebAuthn,
}

impl TryFrom<SignatureType> for StoredSignatureType {
    type Error = crate::error::TempoPrecompileError;

    fn try_from(value: SignatureType) -> std::result::Result<Self, Self::Error> {
        match value {
            SignatureType::Secp256k1 => Ok(Self::Secp256k1),
            SignatureType::P256 => Ok(Self::P256),
            SignatureType::WebAuthn => Ok(Self::WebAuthn),
            _ => Err(AccountKeychainError::invalid_signature_type().into()),
        }
    }
}

impl From<StoredSignatureType> for SignatureType {
    fn from(value: StoredSignatureType) -> Self {
        match value {
            StoredSignatureType::Secp256k1 => Self::Secp256k1,
            StoredSignatureType::P256 => Self::P256,
            StoredSignatureType::WebAuthn => Self::WebAuthn,
        }
    }
}

/// Account Keychain contract for managing authorized keys (session keys, spending limits).
///
/// The struct fields define the on-chain storage layout; the `#[contract]` macro generates the
/// storage handlers which provide an ergonomic way to interact with the EVM state.
#[contract(addr = ACCOUNT_KEYCHAIN_ADDRESS)]
pub struct AccountKeychain {
    // keys[account][keyId] -> AuthorizedKey
    keys: Mapping<Address, Mapping<Address, AuthorizedKey>>,
    // spendingLimits[(account, keyId)][token] -> { remaining, max, period, period_end }
    // Using a hash of account and keyId as the key to avoid triple nesting
    spending_limits: Mapping<B256, Mapping<Address, SpendingLimitState>>,

    // key_scopes[(account, keyId)] -> call scoping configuration.
    key_scopes: Mapping<B256, KeyScope>,

    // key_authorization_witnesses[account][witness] -> true once manually burned.
    key_authorization_witnesses: Mapping<Address, Mapping<B256, bool>>,

    // WARNING(rusowsky): transient storage slots must always be placed at the very end until the `contract`
    // macro is refactored and has 2 independent layouts (persistent and transient).
    // If new (persistent) storage fields need to be added to the precompile, they must go above this one.
    transaction_key: Address,
    // The transaction origin (tx.origin) - the EOA that signed the transaction.
    // Used to ensure spending limits only apply when msg_sender == tx_origin.
    tx_origin: Address,
}

/// Key-level call scope.
///
/// This is the only level that needs an explicit mode bit: an empty `targets` set is ambiguous
/// between "unrestricted" and "scoped deny-all". `is_scoped = false` means ignore the tree and
/// allow any call, while `is_scoped = true && targets.is_empty()` means the key currently allows
/// no targets.
#[derive(Debug, Clone, Storable, Default)]
pub struct KeyScope {
    pub is_scoped: bool,
    pub targets: Set<Address>,
    pub target_scopes: Mapping<Address, TargetScope>,
}

/// Target-level scope for one target under one account key.
///
/// Only persisted for targets present in the parent `targets` set. An empty `selectors` set means
/// any selector on the target is allowed; deleting the target from `targets` removes the scope.
/// This asymmetry is intentional: once the parent target is explicitly allowed, an empty child set
/// means "no further restriction", not "deny all selectors".
#[derive(Debug, Clone, Storable, Default)]
pub struct TargetScope {
    pub selectors: Set<FixedBytes<4>>,
    pub selector_scopes: Mapping<FixedBytes<4>, SelectorScope>,
}

/// Selector-level scope for one selector under one target.
///
/// Only persisted for selectors present in the parent `selectors` set. An empty `recipients` set
/// means any recipient is allowed; deleting the selector from `selectors` removes the scope.
/// Future incremental remove APIs must delete the selector entry when the last recipient is
/// removed; leaving an existing selector with `recipients = []` would widen permissions to
/// allow-all recipients.
#[derive(Debug, Clone, Storable, Default)]
pub struct SelectorScope {
    pub recipients: Set<Address>,
}

/// Per-token spending limit state.
///
/// `remaining` stays in the first slot so the legacy `spending_limits` layout remains intact.
/// It remains `U256` for the same reason, even though T3 caps `max` to TIP-20's `u128` supply
/// range and runtime logic maintains `remaining <= max` for periodic limits.
/// T3+ extends the same row with period metadata in later slots.
#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
pub struct SpendingLimitState {
    /// Remaining amount currently available to spend.
    pub remaining: U256,
    /// Maximum amount allowed per period, capped to TIP-20's `u128` supply range.
    pub max: u128,
    /// Duration of each period in seconds. `0` means non-periodic.
    pub period: u64,
    /// End timestamp of the current period window.
    pub period_end: u64,
}

impl SpendingLimitState {
    /// Computes the period end for the current rollover window, saturating on
    /// all intermediate operations to avoid overflow in extreme timestamps.
    fn compute_next_period_end(&self, current_timestamp: u64) -> u64 {
        debug_assert!(
            self.period != 0,
            "period rollovers require a non-zero period"
        );
        let elapsed = current_timestamp.saturating_sub(self.period_end);
        let periods_elapsed = (elapsed / self.period).saturating_add(1);
        let advance = self.period.saturating_mul(periods_elapsed);
        self.period_end.saturating_add(advance)
    }
}

impl AccountKeychain {
    /// Create a hash key for account+key scoped storage rows.
    ///
    /// This is used to access account-key rows like `spending_limits[key][token]` and
    /// `key_scopes[key]`. The hash combines account and key_id to avoid triple nesting.
    pub fn spending_limit_key(account: Address, key_id: Address) -> B256 {
        let mut data = [0u8; 40];
        data[..20].copy_from_slice(account.as_slice());
        data[20..].copy_from_slice(key_id.as_slice());
        keccak256(data)
    }

    #[inline]
    fn t3_spending_limit_cap(limit: U256) -> Result<u128> {
        if limit > U256::from(u128::MAX) {
            return Err(AccountKeychainError::invalid_spending_limit().into());
        }

        Ok(limit.to::<u128>())
    }

    /// Initializes the account keychain precompile.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Registers a new access key with signature type, expiry, and optional per-token spending
    /// limits. Only callable with the account's root key or, on T6+, an admin access key.
    ///
    /// # Errors
    /// - `UnauthorizedCaller` — only the root key or, on T6+, an admin access key can
    ///   authorize keys, and for contract callers on T2+, `msg.sender` must match `tx.origin`
    /// - `ZeroPublicKey` — `keyId` cannot be the zero address
    /// - `ExpiryInPast` — expiry must be in the future (enforced since T0)
    /// - `KeyAlreadyExists` — a key with this ID is already registered
    /// - `KeyAlreadyRevoked` — revoked keys cannot be re-authorized
    /// - `InvalidSignatureType` — must be Secp256k1, P256, or WebAuthn
    pub fn authorize_key(
        &mut self,
        msg_sender: Address,
        key_id: Address,
        signature_type: SignatureType,
        config: KeyRestrictions,
        witness: Option<B256>,
    ) -> Result<()> {
        self.authorize_key_internal(msg_sender, key_id, signature_type, config, witness, false)
    }

    fn authorize_key_internal(
        &mut self,
        msg_sender: Address,
        key_id: Address,
        signature_type: SignatureType,
        config: KeyRestrictions,
        witness: Option<B256>,
        is_admin: bool,
    ) -> Result<()> {
        let config = &config;
        self.ensure_admin_caller(msg_sender)?;
        let is_t3 = self.storage.spec().is_t3();

        // Validate inputs
        if key_id == Address::ZERO {
            return Err(AccountKeychainError::zero_public_key().into());
        }
        // Admin keys are explicit access-key rows; the root key remains implicit.
        if is_admin && key_id == msg_sender {
            return Err(AccountKeychainError::invalid_key_id().into());
        }

        // T0+: Expiry must be in the future (also catches expiry == 0 which means "key doesn't exist")
        if self.storage.spec().is_t0() {
            let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
            if config.expiry <= current_timestamp {
                return Err(AccountKeychainError::expiry_in_past().into());
            }
        }

        // Check if key already exists (key exists if expiry > 0)
        let existing_key = self.keys[msg_sender][key_id].read()?;
        if existing_key.expiry > 0 {
            return Err(AccountKeychainError::key_already_exists().into());
        }

        // Check if this key was previously revoked - prevents replay attacks
        if existing_key.is_revoked {
            return Err(AccountKeychainError::key_already_revoked().into());
        }

        let signature_type = StoredSignatureType::try_from(signature_type)?;

        // TIP-1011 fields are hardfork-gated at T3, so reject them before mutating state.
        let allowed_call_configs = if is_t3 {
            if config.enforceLimits {
                let mut seen_tokens = HashSet::with_capacity(config.limits.len());
                for limit in &config.limits {
                    if !seen_tokens.insert(limit.token) {
                        return Err(AccountKeychainError::invalid_spending_limit().into());
                    }
                }
            }

            if config.allowAnyCalls {
                // T5+: prevent footguns where callers accidentally pass scopes with allow-all.
                if self.storage.spec().is_t5() && !config.allowedCalls.is_empty() {
                    return Err(AccountKeychainError::invalid_call_scope().into());
                }

                None
            } else {
                Some(config.allowedCalls.as_slice())
            }
        } else {
            if config.limits.iter().any(|limit| limit.period != 0) {
                return Err(AccountKeychainError::invalid_spending_limit().into());
            }

            if !config.allowAnyCalls || !config.allowedCalls.is_empty() {
                return Err(AccountKeychainError::invalid_call_scope().into());
            }

            None
        };

        if let Some(witness) = witness {
            self.ensure_key_authorization_witness_not_burned(msg_sender, witness)?;
        }

        // Create and store the new key
        let new_key = AuthorizedKey {
            signature_type,
            expiry: config.expiry,
            enforce_limits: config.enforceLimits,
            is_revoked: false,
            is_admin,
        };

        self.keys[msg_sender][key_id].write(new_key)?;

        if !is_admin {
            let limits = config
                .enforceLimits
                .then_some(config.limits.iter())
                .into_iter()
                .flatten();

            self.apply_key_authorization_restrictions(
                msg_sender,
                key_id,
                limits,
                allowed_call_configs,
            )?;
        }

        if let Some(witness) = witness {
            self.emit_event(AccountKeychainEvent::KeyAuthorizationWitness(
                IAccountKeychain::KeyAuthorizationWitness {
                    account: msg_sender,
                    witness,
                },
            ))?;
        }

        // Emit event
        self.emit_event(AccountKeychainEvent::key_authorized(
            msg_sender,
            key_id,
            signature_type as u8,
            config.expiry,
        ))?;

        Ok(())
    }

    /// Registers a new unrestricted admin access key. Only newly authorized key IDs can become
    /// admin keys; existing or previously revoked keys must not be upgraded in place.
    pub fn authorize_admin_key(
        &mut self,
        msg_sender: Address,
        key_id: Address,
        signature_type: SignatureType,
        witness: Option<B256>,
    ) -> Result<()> {
        self.authorize_key_internal(
            msg_sender,
            key_id,
            signature_type,
            KeyRestrictions {
                expiry: u64::MAX,
                enforceLimits: false,
                limits: Vec::new(),
                allowAnyCalls: true,
                allowedCalls: Vec::new(),
            },
            witness,
            true,
        )?;
        self.emit_event(AccountKeychainEvent::admin_key_authorized(
            msg_sender, key_id,
        ))
    }

    /// Burns a TIP-1053 witness without authorizing a key.
    pub fn burn_key_authorization_witness(
        &mut self,
        msg_sender: Address,
        call: burnKeyAuthorizationWitnessCall,
    ) -> Result<()> {
        self.ensure_admin_caller(msg_sender)?;
        self.burn_key_authorization_witness_value(msg_sender, call.witness)
    }

    /// Permanently revokes an access key. Once revoked, a key ID can never be re-authorized for
    /// this account, preventing replay of old `KeyAuthorization` signatures.
    ///
    /// # Errors
    /// - `UnauthorizedCaller` — only the root key or, on T6+, an admin access key can revoke;
    ///   for contract callers on T2+, `msg.sender` must match `tx.origin`
    /// - `KeyNotFound` — no key registered with this ID
    pub fn revoke_key(&mut self, msg_sender: Address, call: revokeKeyCall) -> Result<()> {
        self.ensure_admin_caller(msg_sender)?;

        let key = self.keys[msg_sender][call.keyId].read()?;

        // Key exists if expiry > 0
        if key.expiry == 0 {
            return Err(AccountKeychainError::key_not_found().into());
        }

        // Mark the key as revoked - this prevents replay attacks by ensuring
        // the same key_id can never be re-authorized for this account.
        // We keep is_revoked=true but clear other fields.
        let revoked_key = AuthorizedKey {
            is_revoked: true,
            ..Default::default()
        };
        self.keys[msg_sender][call.keyId].write(revoked_key)?;

        // Note: We don't clear spending limits here - they become inaccessible

        // Emit event
        self.emit_event(AccountKeychainEvent::key_revoked(msg_sender, call.keyId))
    }

    /// Updates the spending limit for a key-token pair. Can also convert an unlimited key into a
    /// limited one. Delegates to `load_active_key` for existence/revocation/expiry checks.
    ///
    /// # Errors
    /// - `UnauthorizedCaller` — the transaction wasn't signed by the root key or, on T6+, an
    ///   admin access key, or on T2+ contract callers where `msg.sender != tx.origin`
    /// - `InvalidKeyId` — on T6+, `keyId` cannot be an admin access key
    /// - `KeyAlreadyRevoked` — the target key has been permanently revoked
    /// - `KeyNotFound` — no key is registered under the given `keyId`
    /// - `KeyExpired` — the key's expiry is at or before the current block timestamp
    pub fn update_spending_limit(
        &mut self,
        msg_sender: Address,
        call: updateSpendingLimitCall,
    ) -> Result<()> {
        self.ensure_admin_caller(msg_sender)?;

        let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
        let mut key = self.load_active_key(msg_sender, call.keyId, current_timestamp)?;
        if key.is_admin {
            return Err(AccountKeychainError::invalid_key_id().into());
        }

        // If this key had unlimited spending (enforce_limits=false), enable limits now
        if !key.enforce_limits {
            key.enforce_limits = true;
            self.keys[msg_sender][call.keyId].write(key)?;
        }

        // Update the spending limit
        let limit_key = Self::spending_limit_key(msg_sender, call.keyId);
        if self.storage.spec().is_t3() {
            // T3: newLimit updates both the configured cap and current remaining amount,
            // while preserving period + period_end.
            let mut limit_state = self.spending_limits[limit_key][call.token].read()?;
            limit_state.remaining = call.newLimit;
            limit_state.max = Self::t3_spending_limit_cap(call.newLimit)?;
            self.spending_limits[limit_key][call.token].write(limit_state)?;
        } else {
            self.spending_limits[limit_key][call.token]
                .remaining
                .write(call.newLimit)?;
        }

        // Emit event
        self.emit_event(AccountKeychainEvent::spending_limit_updated(
            msg_sender,
            call.keyId,
            call.token,
            call.newLimit,
        ))
    }

    /// Returns key info for the given account-key pair, or a blank entry if inexistent or revoked.
    pub fn get_key(&self, call: getKeyCall) -> Result<KeyInfo> {
        let key = self.keys[call.account][call.keyId].read()?;

        // Key doesn't exist if expiry == 0, or key has been revoked
        if key.expiry == 0 || key.is_revoked {
            return Ok(KeyInfo {
                signatureType: SignatureType::Secp256k1,
                keyId: Address::ZERO,
                expiry: 0,
                enforceLimits: false,
                isRevoked: key.is_revoked,
            });
        }

        Ok(KeyInfo {
            signatureType: key.signature_type.into(),
            keyId: call.keyId,
            expiry: key.expiry,
            enforceLimits: key.enforce_limits,
            isRevoked: key.is_revoked,
        })
    }

    /// Returns the remaining spending limit for a key-token pair.
    ///
    /// T2+ returns zero for missing, revoked, or expired keys. Pre-T2 preserves the historical
    /// behavior of reading the raw stored remaining amount so old blocks reexecute identically.
    pub fn get_remaining_limit(&self, call: getRemainingLimitCall) -> Result<U256> {
        if !self.storage.spec().is_t2() {
            let limit_key = Self::spending_limit_key(call.account, call.keyId);
            return self.spending_limits[limit_key][call.token].remaining.read();
        }

        self.get_remaining_limit_with_period(getRemainingLimitWithPeriodCall {
            account: call.account,
            keyId: call.keyId,
            token: call.token,
        })
        .map(|ret| ret.remaining)
    }

    /// Returns the remaining spending limit together with the active period end timestamp.
    ///
    /// Missing, revoked, or expired keys report zeroed values instead of erroring.
    pub fn get_remaining_limit_with_period(
        &self,
        call: getRemainingLimitWithPeriodCall,
    ) -> Result<getRemainingLimitReturn> {
        let (remaining, period_end) = self.effective_limit_state(
            call.account,
            call.keyId,
            call.token,
            self.storage.timestamp().saturating_to::<u64>(),
        )?;

        Ok(getRemainingLimitReturn {
            remaining,
            periodEnd: period_end,
        })
    }

    /// Root/admin-only create-or-replace updates for one or more target call scopes.
    pub fn set_allowed_calls(
        &mut self,
        msg_sender: Address,
        call: setAllowedCallsCall,
    ) -> Result<()> {
        if !self.storage.spec().is_t3() {
            return Err(AccountKeychainError::invalid_call_scope().into());
        }

        self.ensure_admin_caller(msg_sender)?;

        let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
        let key = self.load_active_key(msg_sender, call.keyId, current_timestamp)?;
        if key.is_admin {
            return Err(AccountKeychainError::invalid_key_id().into());
        }

        let key_hash = Self::spending_limit_key(msg_sender, call.keyId);
        let scopes = call.scopes;

        if scopes.is_empty() {
            return Err(AccountKeychainError::invalid_call_scope().into());
        }

        self.validate_call_scopes(&scopes)?;

        for scope in &scopes {
            self.upsert_target_scope(key_hash, scope)?;
        }

        self.key_scopes[key_hash].is_scoped.write(true)
    }

    /// Root/admin-only removal of one target call scope.
    pub fn remove_allowed_calls(
        &mut self,
        msg_sender: Address,
        call: removeAllowedCallsCall,
    ) -> Result<()> {
        self.ensure_admin_caller(msg_sender)?;

        let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
        let key = self.load_active_key(msg_sender, call.keyId, current_timestamp)?;
        if key.is_admin {
            return Err(AccountKeychainError::invalid_key_id().into());
        }

        let key_hash = Self::spending_limit_key(msg_sender, call.keyId);
        let current_mode = self.key_scopes[key_hash].is_scoped.read()?;
        if !current_mode {
            return Ok(());
        }

        self.remove_target_scope(key_hash, call.target)?;

        Ok(())
    }

    /// Returns whether an account key is call-scoped together with its configured call scopes.
    ///
    /// `isScoped = false` means unrestricted. `isScoped = true` with an empty `scopes` vec means
    /// the key is scoped but currently allows no targets. Missing, revoked, or expired access
    /// keys also report scoped deny-all so this getter never exposes stale persisted scope state.
    pub fn get_allowed_calls(&self, call: getAllowedCallsCall) -> Result<getAllowedCallsReturn> {
        if call.keyId.is_zero() {
            return Ok(getAllowedCallsReturn {
                isScoped: false,
                scopes: Vec::new(),
            });
        }

        let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
        let key = self.keys[call.account][call.keyId].read()?;
        if key.expiry == 0 || key.is_revoked || current_timestamp >= key.expiry {
            return Ok(getAllowedCallsReturn {
                isScoped: true,
                scopes: Vec::new(),
            });
        }

        let key_hash = Self::spending_limit_key(call.account, call.keyId);
        let is_scoped = self.key_scopes[key_hash].is_scoped.read()?;

        if !is_scoped {
            return Ok(getAllowedCallsReturn {
                isScoped: false,
                scopes: Vec::new(),
            });
        }

        let targets = self.key_scopes[key_hash].targets.read()?;
        let mut scopes = Vec::new();
        for target in targets {
            let selectors = self.key_scopes[key_hash].target_scopes[target]
                .selectors
                .read()?;

            let scope = if selectors.is_empty() {
                CallScope {
                    target,
                    selectorRules: Vec::new(),
                }
            } else {
                let mut rules = Vec::new();

                for selector in selectors {
                    let recipients: Vec<Address> = self.key_scopes[key_hash].target_scopes[target]
                        .selector_scopes[selector]
                        .recipients
                        .read()?
                        .into();

                    rules.push(SelectorRule {
                        selector,
                        recipients,
                    });
                }

                CallScope {
                    target,
                    selectorRules: rules,
                }
            };

            scopes.push(scope);
        }

        Ok(getAllowedCallsReturn {
            isScoped: true,
            scopes,
        })
    }

    /// Returns whether a TIP-1053 key-authorization witness has been manually burned.
    pub fn is_key_authorization_witness_burned(
        &self,
        call: isKeyAuthorizationWitnessBurnedCall,
    ) -> Result<bool> {
        self.key_authorization_witnesses[call.account][call.witness].read()
    }

    /// Returns true for the root key or for an active admin access key.
    /// Returns the access key used to authorize the current transaction (`Address::ZERO` = root key).
    pub fn get_transaction_key(
        &self,
        _call: getTransactionKeyCall,
        _msg_sender: Address,
    ) -> Result<Address> {
        self.transaction_key.t_read()
    }

    /// Internal: Set the transaction key (called during transaction validation)
    ///
    /// SECURITY CRITICAL: This must be called by the transaction validation logic
    /// BEFORE the transaction is executed, to store which key authorized the transaction.
    /// - If key_id is Address::ZERO (main key), this should store Address::ZERO
    /// - If key_id is a specific key address, this should store that key
    ///
    /// This creates a secure channel between validation and the precompile to ensure
    /// root/admin checks can distinguish root-signed transactions from access-key-signed
    /// transactions.
    /// Uses transient storage, so the key is automatically cleared after the transaction.
    pub fn set_transaction_key(&mut self, key_id: Address) -> Result<()> {
        self.transaction_key.t_write(key_id)
    }

    /// Sets the transaction origin (tx.origin) for the current transaction.
    ///
    /// Called by the handler before transaction execution.
    /// Uses transient storage, so it's automatically cleared after the transaction.
    pub fn set_tx_origin(&mut self, origin: Address) -> Result<()> {
        self.tx_origin.t_write(origin)
    }

    /// Persists the authorization-time restrictions for a freshly created key.
    ///
    /// T0-T2 only store raw spending limits. T3 additionally seeds periodic metadata and replaces
    /// the key's call-scope tree in one pass.
    fn apply_key_authorization_restrictions<'a>(
        &mut self,
        account: Address,
        key_id: Address,
        limits: impl IntoIterator<Item = &'a TokenLimit>,
        allowed_calls: Option<&[CallScope]>,
    ) -> Result<()> {
        let limit_key = Self::spending_limit_key(account, key_id);

        let is_t3 = self.storage.spec().is_t3();
        debug_assert!(is_t3 || allowed_calls.is_none());

        let now = self.storage.timestamp().saturating_to::<u64>();
        for limit in limits {
            if is_t3 {
                let period_end = if limit.period == 0 {
                    0
                } else {
                    now.saturating_add(limit.period)
                };

                self.spending_limits[limit_key][limit.token].write(SpendingLimitState {
                    remaining: limit.amount,
                    max: Self::t3_spending_limit_cap(limit.amount)?,
                    period: limit.period,
                    period_end,
                })?;
            } else {
                self.spending_limits[limit_key][limit.token]
                    .remaining
                    .write(limit.amount)?;
            }
        }

        if !is_t3 {
            return Ok(());
        }

        self.replace_allowed_calls(limit_key, allowed_calls)
    }

    /// Validates a top-level call against scoped permissions for this key.
    ///
    /// Validation walks the scope tree from coarse to fine:
    /// - `is_scoped = false` => unrestricted key
    /// - target missing from `targets` => target denied
    /// - target present with `selectors = []` => allow any selector on that target
    /// - selector missing from `selectors` => selector denied
    /// - selector present with `recipients = []` => allow any recipient for that selector
    pub fn validate_call_scope_for_transaction(
        &self,
        account: Address,
        key_id: Address,
        to: &TxKind,
        input: &[u8],
    ) -> Result<()> {
        if key_id == Address::ZERO || !self.storage.spec().is_t3() {
            return Ok(());
        }

        let target = match to {
            TxKind::Call(target) => *target,
            TxKind::Create => return Err(AccountKeychainError::call_not_allowed().into()),
        };

        let key_hash = Self::spending_limit_key(account, key_id);

        // Key-level scoped flag decides whether this CALL must match the stored scope tree.
        if !self.key_scopes[key_hash].is_scoped.read()? {
            return Ok(());
        }

        if !self.key_scopes[key_hash].targets.contains(&target)? {
            return Err(AccountKeychainError::call_not_allowed().into());
        }

        // Empty child sets mean "no further restriction" once the parent target was explicitly
        // allowed, so a present target with `selectors = []` allows any selector.
        let target_is_unconstrained = self.key_scopes[key_hash].target_scopes[target]
            .selectors
            .is_empty()?;
        if target_is_unconstrained {
            return Ok(());
        }

        if input.len() < 4 {
            return Err(AccountKeychainError::call_not_allowed().into());
        }

        // Scoped targets next match on the 4-byte selector.
        let selector = FixedBytes::<4>::from(
            <[u8; 4]>::try_from(&input[..4]).expect("input len checked above"),
        );
        if !self.key_scopes[key_hash].target_scopes[target]
            .selectors
            .contains(&selector)?
        {
            return Err(AccountKeychainError::call_not_allowed().into());
        }

        // Likewise, a present selector with `recipients = []` means any recipient is allowed.
        let selector_is_unconstrained = self.key_scopes[key_hash].target_scopes[target]
            .selector_scopes[selector]
            .recipients
            .is_empty()?;
        if selector_is_unconstrained {
            return Ok(());
        }

        if input.len() < 36 {
            return Err(AccountKeychainError::call_not_allowed().into());
        }

        // Recipient-constrained selectors only permit ABI-encoded address arguments.
        let recipient_word = &input[4..36];
        if recipient_word[..12].iter().any(|byte| *byte != 0) {
            return Err(AccountKeychainError::call_not_allowed().into());
        }

        let recipient = Address::from_slice(&recipient_word[12..]);
        if self.key_scopes[key_hash].target_scopes[target].selector_scopes[selector]
            .recipients
            .contains(&recipient)?
        {
            Ok(())
        } else {
            Err(AccountKeychainError::call_not_allowed().into())
        }
    }

    /// Replaces the full call-scope tree for an account key.
    ///
    /// `None` switches the key back to unrestricted mode, while `Some([])` preserves scoped mode
    /// with no targets so reads can distinguish scoped deny-all from unrestricted mode. This is
    /// the only place where an empty top-level list means deny-all; below the key level, empty
    /// child sets mean "no further restriction".
    fn replace_allowed_calls(
        &mut self,
        account_key: B256,
        allowed_calls: Option<&[CallScope]>,
    ) -> Result<()> {
        // Fresh authorizations should not have any pre-existing call-scope rows because
        // `authorize_key` rejects both existing and previously revoked keys before reaching this
        // path. We still clear the scope tree first as a defense-in-depth measure against stale or
        // out-of-band state, and keep it because the valid-path cost is low (empty target set).
        self.clear_all_target_scopes(account_key)?;

        match allowed_calls {
            None => {
                self.key_scopes[account_key].is_scoped.write(false)?;
                Ok(())
            }
            Some(scopes) => {
                self.key_scopes[account_key].is_scoped.write(true)?;

                if scopes.is_empty() {
                    return Ok(());
                }

                self.validate_call_scopes(scopes)?;

                for scope in scopes {
                    self.upsert_target_scope(account_key, scope)?;
                }

                Ok(())
            }
        }
    }

    /// Deletes every persisted target scope under an account key.
    fn clear_all_target_scopes(&mut self, account_key: B256) -> Result<()> {
        let targets = self.key_scopes[account_key].targets.read()?;
        for target in targets {
            self.clear_target_selectors(account_key, target)?;
        }

        self.key_scopes[account_key].targets.delete()
    }

    /// Deletes one target scope and all nested selector/recipient rows beneath it.
    fn remove_target_scope(&mut self, account_key: B256, target: Address) -> Result<()> {
        if !self.key_scopes[account_key].targets.remove(&target)? {
            return Ok(());
        }

        self.clear_target_selectors(account_key, target)
    }

    /// Clears every selector scope stored under one target.
    fn clear_target_selectors(&mut self, account_key: B256, target: Address) -> Result<()> {
        let selectors = self.key_scopes[account_key].target_scopes[target]
            .selectors
            .read()?;
        for selector in selectors {
            self.key_scopes[account_key].target_scopes[target].selector_scopes[selector]
                .recipients
                .delete()?;
        }

        self.key_scopes[account_key].target_scopes[target]
            .selectors
            .delete()
    }

    /// Creates or replaces one target scope, including all nested selector rules.
    fn upsert_target_scope(&mut self, account_key: B256, scope: &CallScope) -> Result<()> {
        let target = scope.target;

        // Pre-T4: validate call scopes inline
        if !self.storage.spec().is_t4() {
            self.validate_call_scope(scope)?;
        }

        self.key_scopes[account_key].targets.insert(target)?;
        self.clear_target_selectors(account_key, target)?;

        if scope.selectorRules.is_empty() {
            // Keeping the target while clearing nested selector rows intentionally widens this
            // target to allow-all selectors. Future incremental remove APIs must delete the target
            // instead of leaving `selectors = []` behind accidentally.
            return Ok(());
        }

        for rule in &scope.selectorRules {
            let selector = rule.selector;
            self.key_scopes[account_key].target_scopes[target]
                .selectors
                .insert(selector)?;

            if rule.recipients.is_empty() {
                if !self.storage.spec().is_t4() {
                    // Keep the pre-T4 empty-set delete to preserve the original storage-touch
                    // pattern. Removing it earlier changes same-tx call-scope warmness without
                    // changing persisted state.
                    self.key_scopes[account_key].target_scopes[target].selector_scopes[selector]
                        .recipients
                        .delete()?;
                }
            } else {
                // `validate_selector_rules` already rejected duplicates.
                self.key_scopes[account_key].target_scopes[target].selector_scopes[selector]
                    .recipients
                    .write(Set::new_unchecked(rule.recipients.clone()))?;
            }
        }

        Ok(())
    }

    /// Validates a list of [`CallScope`]s.
    fn validate_call_scopes(&mut self, scopes: &[CallScope]) -> Result<()> {
        // Preserve the incremental pre-T11 validation order for historical reexecution.
        if self.storage.spec().is_t11() {
            if has_duplicates_metered(&mut self.storage, scopes.iter().map(|scope| scope.target))? {
                return Err(AccountKeychainError::invalid_call_scope().into());
            }

            for scope in scopes {
                self.validate_call_scope(scope)?;
            }
            return Ok(());
        }

        let mut seen_targets = HashSet::new();
        for scope in scopes {
            if !seen_targets.insert(scope.target) {
                return Err(AccountKeychainError::invalid_call_scope().into());
            }

            // Post-T4: validate call scopes before inserting
            if self.storage.spec().is_t4() {
                self.validate_call_scope(scope)?;
            }
        }
        Ok(())
    }

    /// Validates a single [`CallScope`].
    fn validate_call_scope(&mut self, scope: &CallScope) -> Result<()> {
        // The public API uses the absence of a target to block it, so persisting address(0) as a
        // real target is always confusing and serves no useful purpose.
        if scope.target.is_zero() {
            return Err(AccountKeychainError::invalid_call_scope().into());
        }

        if !scope.selectorRules.is_empty() {
            self.validate_selector_rules(scope.target, &scope.selectorRules)?;
        }

        Ok(())
    }

    /// Validates per-selector scope rules for one target before they are persisted.
    ///
    /// `recipients = []` is an explicit allow-all sentinel at the selector level. To deny a
    /// selector entirely, omit it from `selectorRules` or remove the target scope instead of
    /// leaving behind an empty child set via incremental mutation.
    fn validate_selector_rules(&mut self, target: Address, rules: &[SelectorRule]) -> Result<()> {
        let spec = self.storage.spec();
        let sort_selectors = spec.is_t11();

        let mut cached_is_tip20: Option<bool> = None;
        let mut is_tip20 = || -> Result<bool> {
            match cached_is_tip20 {
                Some(v) => Ok(v),
                None => Ok(*cached_is_tip20.insert({
                    if !spec.is_t4() {
                        // Pre-T4: validate that TIP-20 is initialized
                        TIP20Factory::new().is_tip20(target)?
                    } else {
                        // Post-T4: only validate the address
                        target.is_tip20()
                    }
                })),
            }
        };

        if sort_selectors
            && has_duplicates_metered(&mut self.storage, rules.iter().map(|rule| rule.selector))?
        {
            return Err(AccountKeychainError::invalid_call_scope().into());
        }

        let mut selectors = HashSet::new();
        for rule in rules {
            if !sort_selectors && !selectors.insert(rule.selector) {
                return Err(AccountKeychainError::invalid_call_scope().into());
            }

            if rule.recipients.is_empty() {
                continue;
            }

            if !is_constrained_tip20_selector(*rule.selector) || !is_tip20()? {
                return Err(AccountKeychainError::invalid_call_scope().into());
            }

            if rule.recipients.iter().any(|recipient| recipient.is_zero())
                || has_duplicates_metered(&mut self.storage, rule.recipients.iter().copied())?
            {
                return Err(AccountKeychainError::invalid_call_scope().into());
            }
        }

        Ok(())
    }

    /// Ensures admin operations are authorized for this caller.
    ///
    /// Rules:
    /// - transaction must be signed by the root key (`transaction_key == Address::ZERO`) or,
    ///   on T6+, an active admin access key
    /// - T2+: caller must match tx.origin
    ///
    /// # Errors
    /// - `UnauthorizedCaller` when the transaction is signed by a non-admin access key
    /// - `UnauthorizedCaller` on T2+ when `msg.sender != tx.origin`
    /// - storage read errors from transient key/origin or account metadata lookups
    ///
    /// The T2 check prevents transaction-global root-key status from being reused by
    /// intermediate contracts (confused-deputy self-administration).
    ///
    /// `tx_origin` is seeded by the handler before validation/execution.
    /// If origin is not seeded (zero), admin ops are rejected.
    fn ensure_admin_caller(&self, msg_sender: Address) -> Result<()> {
        let transaction_key = self.transaction_key.t_read()?;
        if !transaction_key.is_zero()
            && (!self.storage.spec().is_t6() || !self.is_admin_key(msg_sender, transaction_key)?)
        {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }

        if self.storage.spec().is_t2() {
            let tx_origin = self.tx_origin.t_read()?;
            if tx_origin.is_zero() || tx_origin != msg_sender {
                return Err(AccountKeychainError::unauthorized_caller().into());
            }
        }

        Ok(())
    }

    /// Internal predicate for root/admin status.
    ///
    /// Warning: this returns true when `key_id == account`, because the root key
    /// is implicitly admin even when it is not stored as an access key.
    pub fn is_admin_key(&self, account: Address, key_id: Address) -> Result<bool> {
        if key_id == account {
            return Ok(true);
        }

        let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
        let key = match self.load_active_key(account, key_id, current_timestamp) {
            Ok(key) => key,
            Err(err) if err.is_system_error() => return Err(err),
            Err(_) => return Ok(false),
        };

        Ok(key.is_admin)
    }

    /// Internal predicate for active key status.
    pub fn is_active_key(&self, account: Address, key_id: Address) -> Result<bool> {
        let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
        match self.load_active_key(account, key_id, current_timestamp) {
            Ok(_) => Ok(true),
            Err(err) if err.is_system_error() => Err(err),
            Err(_) => Ok(false),
        }
    }

    fn ensure_key_authorization_witness_not_burned(
        &self,
        account: Address,
        witness: B256,
    ) -> Result<()> {
        if self.key_authorization_witnesses[account][witness].read()? {
            return Err(AccountKeychainError::key_authorization_witness_already_burned().into());
        }

        Ok(())
    }

    fn burn_key_authorization_witness_value(
        &mut self,
        account: Address,
        witness: B256,
    ) -> Result<()> {
        self.ensure_key_authorization_witness_not_burned(account, witness)?;

        self.key_authorization_witnesses[account][witness].write(true)?;
        self.emit_event(AccountKeychainEvent::KeyAuthorizationWitnessBurned(
            IAccountKeychain::KeyAuthorizationWitnessBurned { account, witness },
        ))
    }

    /// Load and validate a key exists, is not revoked, and is not expired.
    ///
    /// Returns the key if valid, or an error if:
    /// - Key doesn't exist (expiry == 0)
    /// - Key has been revoked
    /// - Key has expired at or before `current_timestamp`
    fn load_active_key(
        &self,
        account: Address,
        key_id: Address,
        current_timestamp: u64,
    ) -> Result<AuthorizedKey> {
        let key = self.keys[account][key_id].read()?;

        if key.is_revoked {
            return Err(AccountKeychainError::key_already_revoked().into());
        }

        if key.expiry == 0 {
            return Err(AccountKeychainError::key_not_found().into());
        }

        if current_timestamp >= key.expiry {
            return Err(AccountKeychainError::key_expired().into());
        }

        Ok(key)
    }

    /// Validate keychain authorization (existence, revocation, expiry, and optionally signature type).
    ///
    /// # Arguments
    /// * `account` - The account that owns the key
    /// * `key_id` - The key identifier to validate
    /// * `current_timestamp` - Current block timestamp for expiry check
    /// * `expected_sig_type` - The signature type from the actual signature (0=Secp256k1, 1=P256,
    ///   2=WebAuthn). Pass `None` to skip validation (for backward compatibility pre-T1).
    ///
    /// # Errors
    /// - `KeyAlreadyRevoked` — the key has been permanently revoked
    /// - `KeyNotFound` — no key is registered under the given `key_id`
    /// - `KeyExpired` — `current_timestamp` is at or past the key's expiry
    /// - `SignatureTypeMismatch` — the key's stored type differs from `expected_sig_type`
    pub fn validate_keychain_authorization(
        &self,
        account: Address,
        key_id: Address,
        current_timestamp: u64,
        expected_sig_type: Option<u8>,
    ) -> Result<AuthorizedKey> {
        let key = self.load_active_key(account, key_id, current_timestamp)?;

        // Validate that the signature type matches the key type stored in the keychain
        // Only check if expected_sig_type is provided (T1+ hardfork)
        if let Some(sig_type) = expected_sig_type
            && key.signature_type as u8 != sig_type
        {
            return Err(AccountKeychainError::signature_type_mismatch(
                key.signature_type as u8,
                sig_type,
            )
            .into());
        }

        Ok(key)
    }

    /// Computes the effective remaining limit at `current_timestamp` without mutating storage.
    pub fn effective_remaining_limit(
        &self,
        account: Address,
        key_id: Address,
        token: Address,
        current_timestamp: u64,
    ) -> Result<U256> {
        self.effective_limit_state(account, key_id, token, current_timestamp)
            .map(|(remaining, _)| remaining)
    }

    /// Computes the effective remaining limit using an already-loaded key.
    pub fn effective_remaining_limit_with_key(
        &self,
        account: Address,
        key_id: Address,
        token: Address,
        current_timestamp: u64,
        key: &AuthorizedKey,
    ) -> Result<U256> {
        if key_id.is_zero() && self.storage.spec().is_t3() {
            return Ok(U256::ZERO);
        }

        self.effective_limit_state_with_key(account, key_id, token, current_timestamp, key)
            .map(|(remaining, _)| remaining)
    }

    /// Computes the effective remaining limit and period end at `current_timestamp`
    /// without mutating storage.
    fn effective_limit_state(
        &self,
        account: Address,
        key_id: Address,
        token: Address,
        current_timestamp: u64,
    ) -> Result<(U256, u64)> {
        if key_id.is_zero() && self.storage.spec().is_t3() {
            return Ok((U256::ZERO, 0));
        }

        let key = self.keys[account][key_id].read()?;

        self.effective_limit_state_with_key(account, key_id, token, current_timestamp, &key)
    }

    fn effective_limit_state_with_key(
        &self,
        account: Address,
        key_id: Address,
        token: Address,
        current_timestamp: u64,
        key: &AuthorizedKey,
    ) -> Result<(U256, u64)> {
        // T2+: return zero if key doesn't exist or has been revoked
        if key.is_revoked || key.expiry == 0 {
            return Ok((U256::ZERO, 0));
        }

        // T3+: return zero if key has expired
        if current_timestamp >= key.expiry && self.storage.spec().is_t3() {
            return Ok((U256::ZERO, 0));
        }

        let limit_key = Self::spending_limit_key(account, key_id);
        let remaining = self.spending_limits[limit_key][token].remaining.read()?;

        if !self.storage.spec().is_t3() {
            return Ok((remaining, 0));
        }

        let period = self.spending_limits[limit_key][token].period.read()?;
        if period == 0 {
            return Ok((remaining, 0));
        }

        let remaining =
            if self.storage.spec().is_t7() && remaining == ZERO_PERIODIC_REMAINING_SENTINEL {
                U256::ZERO
            } else {
                remaining
            };

        let period_end = self.spending_limits[limit_key][token].period_end.read()?;
        if current_timestamp < period_end {
            return Ok((remaining, period_end));
        }

        let elapsed = current_timestamp.saturating_sub(period_end);
        let periods_elapsed = (elapsed / period).saturating_add(1);
        let advance = period.saturating_mul(periods_elapsed);
        let next_end = period_end.saturating_add(advance);

        let max = self.spending_limits[limit_key][token].max.read()?;

        Ok((U256::from(max), next_end))
    }

    /// Deducts `amount` from the key's remaining spending limit for `token`, failing if exceeded.
    ///
    /// # Errors
    /// - `KeyAlreadyRevoked` — the key has been permanently revoked
    /// - `KeyNotFound` — no key is registered under the given `key_id`
    /// - `SpendingLimitExceeded` — `amount` exceeds the key's remaining limit for `token`
    pub fn verify_and_update_spending(
        &mut self,
        account: Address,
        key_id: Address,
        token: Address,
        amount: U256,
    ) -> Result<()> {
        // If using main key (zero address), no spending limits apply
        if key_id == Address::ZERO {
            return Ok(());
        }

        // Check key is valid (exists and not revoked)
        let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
        let key = self.load_active_key(account, key_id, current_timestamp)?;

        // If enforce_limits is false, this key has unlimited spending
        if !key.enforce_limits {
            return Ok(());
        }

        // Check and update spending limit
        let limit_key = Self::spending_limit_key(account, key_id);
        if !self.storage.spec().is_t3() {
            let remaining = self.spending_limits[limit_key][token].remaining.read()?;
            if amount > remaining {
                return Err(AccountKeychainError::spending_limit_exceeded().into());
            }

            let new_remaining = remaining - amount;
            self.spending_limits[limit_key][token]
                .remaining
                .write(new_remaining)?;
            return Ok(());
        }

        let mut limit_state = self.spending_limits[limit_key][token].read()?;
        let mut remaining = limit_state.remaining;
        let is_periodic = limit_state.period != 0;

        if is_periodic {
            if self.storage.spec().is_t7() && remaining == ZERO_PERIODIC_REMAINING_SENTINEL {
                remaining = U256::ZERO;
            }

            if current_timestamp >= limit_state.period_end {
                let next_end = limit_state.compute_next_period_end(current_timestamp);

                remaining = U256::from(limit_state.max);
                limit_state.remaining = remaining;
                limit_state.period_end = next_end;
            }
        }

        if amount > remaining {
            return Err(AccountKeychainError::spending_limit_exceeded().into());
        }

        // Update remaining limit
        let new_remaining = remaining - amount;
        if is_periodic {
            if self.storage.spec().is_t7() && new_remaining.is_zero() {
                limit_state.remaining = ZERO_PERIODIC_REMAINING_SENTINEL;
            } else {
                limit_state.remaining = new_remaining;
            }
            self.spending_limits[limit_key][token].write(limit_state)?;
        } else {
            self.spending_limits[limit_key][token]
                .remaining
                .write(new_remaining)?;
        }

        self.emit_event(AccountKeychainEvent::access_key_spend(
            account,
            key_id,
            token,
            amount,
            new_remaining,
        ))?;

        Ok(())
    }

    /// Refund spending limit after a fee refund.
    ///
    /// Restores the spending limit by the refunded amount.
    /// Should be called after a fee refund to avoid permanently reducing the spending limit.
    /// On T3, this should never restore more than the configured max in the current fee flow,
    /// but we still clamp as defense in depth in case a future caller violates that invariant.
    pub fn refund_spending_limit(
        &mut self,
        account: Address,
        token: Address,
        amount: U256,
    ) -> Result<()> {
        let transaction_key = self.transaction_key.t_read()?;

        if transaction_key == Address::ZERO {
            return Ok(());
        }

        let tx_origin = self.tx_origin.t_read()?;
        if account != tx_origin {
            return Ok(());
        }

        // Silently skip refund if the key was revoked or expired — the fee was already
        // collected and the key is no longer active, so there is nothing to restore.
        let current_timestamp = self.storage.timestamp().saturating_to::<u64>();
        let key = match self.load_active_key(account, transaction_key, current_timestamp) {
            Ok(key) => key,
            Err(err) if err.is_system_error() => return Err(err),
            Err(_) => return Ok(()),
        };

        if !key.enforce_limits {
            return Ok(());
        }

        let limit_key = Self::spending_limit_key(account, transaction_key);
        if !self.storage.spec().is_t3() {
            let remaining = self.spending_limits[limit_key][token].remaining.read()?;
            let refunded = remaining.saturating_add(amount);
            return self.spending_limits[limit_key][token]
                .remaining
                .write(refunded);
        }

        let mut limit_state = self.spending_limits[limit_key][token].read()?;
        // (T7+) decode the periodic zero sentinel before adding the refund.
        let refunded = if self.storage.spec().is_t7()
            && limit_state.period != 0
            && limit_state.remaining == ZERO_PERIODIC_REMAINING_SENTINEL
        {
            amount
        } else {
            limit_state.remaining.saturating_add(amount)
        };

        // Legacy pre-T3 rows only persisted `remaining`, so migrated keys deserialize with
        // `max = 0`. Preserve that legacy behavior and only clamp rows that were configured
        // with a real T3 max.
        limit_state.remaining = if limit_state.max == 0 {
            refunded
        } else {
            refunded.min(U256::from(limit_state.max))
        };

        self.spending_limits[limit_key][token].write(limit_state)
    }

    /// Authorize a token transfer with access key spending limits.
    ///
    /// This method checks if the transaction is using an access key, and if so,
    /// verifies and updates the spending limits for that key.
    /// Should be called before executing a transfer.
    ///
    /// # Errors
    /// - `KeyAlreadyRevoked` — the session key has been permanently revoked
    /// - `KeyNotFound` — no key is registered for the current transaction key
    /// - `SpendingLimitExceeded` — `amount` exceeds the key's remaining limit for `token`
    pub fn authorize_transfer(
        &mut self,
        account: Address,
        token: Address,
        amount: U256,
    ) -> Result<()> {
        // Get the transaction key for this account
        let transaction_key = self.transaction_key.t_read()?;

        // If using main key (Address::ZERO), no spending limits apply
        if transaction_key == Address::ZERO {
            return Ok(());
        }

        // Only apply spending limits if the caller is the tx origin.
        let tx_origin = self.tx_origin.t_read()?;
        if account != tx_origin {
            return Ok(());
        }

        // Verify and update spending limits for this access key
        self.verify_and_update_spending(account, transaction_key, token, amount)
    }

    /// Authorize a token approval with access key spending limits.
    ///
    /// This method checks if the transaction is using an access key, and if so,
    /// verifies and updates the spending limits for that key.
    /// Should be called before executing an approval.
    ///
    /// # Errors
    /// - `KeyAlreadyRevoked` — the session key has been permanently revoked
    /// - `KeyNotFound` — no key is registered for the current transaction key
    /// - `SpendingLimitExceeded` — the approval increase exceeds the remaining limit for `token`
    pub fn authorize_approve(
        &mut self,
        account: Address,
        token: Address,
        old_approval: U256,
        new_approval: U256,
    ) -> Result<()> {
        // Get the transaction key for this account
        let transaction_key = self.transaction_key.t_read()?;

        // If using main key (Address::ZERO), no spending limits apply
        if transaction_key == Address::ZERO {
            return Ok(());
        }

        // Only apply spending limits if the caller is the tx origin.
        let tx_origin = self.tx_origin.t_read()?;
        if account != tx_origin {
            return Ok(());
        }

        // Calculate the increase in approval (only deduct if increasing)
        // If old approval is 100 and new approval is 120, deduct 20 from spending limit
        // If old approval is 100 and new approval is 80, deduct 0 (decreasing approval is free)
        let approval_increase = new_approval.saturating_sub(old_approval);

        // Only check spending limits if there's an increase in approval
        if approval_increase.is_zero() {
            return Ok(());
        }

        // Verify and update spending limits for this access key
        self.verify_and_update_spending(account, transaction_key, token, approval_increase)
    }
}


