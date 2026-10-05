//! [TIP-20] token standard — Tempo's native fungible token implementation.
//!
//! Provides ERC-20-like balances, allowances, and transfers with Tempo extensions:
//! role-based access control, pausability, supply caps, transfer policies ([TIP-403]), opt-in
//! staking rewards, EIP-2612 permits (T2+), quote-token graphs, and virtual addresses ([TIP-1022]).
//!
//! [TIP-20]: <https://docs.tempo.xyz/protocol/tip20>
//! [TIP-403]: <https://docs.tempo.xyz/protocol/tip403>
//! [TIP-1022]: <https://docs.tempo.xyz/protocol/tip1022>

pub mod dispatch;
pub mod rewards;
pub mod roles;

pub use tempo_contracts::precompiles::{
    IRolesAuth, ITIP20, RolesAuthError, RolesAuthEvent, TIP20Error, TIP20Event, USD_CURRENCY,
};
pub use tempo_primitives::is_tip20_prefix;

// Re-export the generated slots module for external access to storage slot constants
pub use slots as tip20_slots;

use crate::{
    PATH_USD_ADDRESS, RECEIVE_POLICY_GUARD_ADDRESS, StorageCtx, TIP_FEE_MANAGER_ADDRESS,
    account_keychain::AccountKeychain,
    address_registry::AddressRegistry,
    error::{Result, TempoPrecompileError},
    receive_policy_guard::{InboundKind, ReceivePolicyGuard, RecoveryMode},
    storage::{Handler, Mapping},
    tip20::{rewards::UserRewardInfo, roles::DEFAULT_ADMIN_ROLE},
    tip20_factory::TIP20Factory,
    tip403_registry::{ALLOW_ALL_POLICY_ID, AuthRole, ITIP403Registry, TIP403Registry},
};
use alloy::{
    primitives::{Address, B256, U256, uint},
    sol_types::SolValue,
};
use keccak_const::Keccak256;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{
    DECIMALS as TIP20_DECIMALS, ReceivePolicyGuardError, STABLECOIN_DEX_ADDRESS,
    TIP20_CHANNEL_RESERVE_ADDRESS,
};
use tempo_precompiles_macros::contract;
use tempo_primitives::TempoAddressExt;
use tracing::trace;

/// u128::MAX as U256
pub const U128_MAX: U256 = uint!(0xffffffffffffffffffffffffffffffff_U256);

/// Validates that the given token's currency is `"USD"`.
///
/// # Errors
/// - `InvalidToken` — address does not have the TIP-20 prefix
/// - `InvalidCurrency` — token currency is not `"USD"`
pub fn validate_usd_currency(token: Address) -> Result<()> {
    if TIP20Token::from_address(token)?.currency()? != USD_CURRENCY {
        return Err(TIP20Error::invalid_currency().into());
    }
    Ok(())
}

/// TIP-20 token contract — the native token standard on Tempo.
///
/// Implements ERC-20-like functionality (balances, allowances, transfers) with additional
/// features: role-based access control, pausability, supply caps, transfer policies ([TIP-403]),
/// virtual addresses ([TIP-1022]), and opt-in staking rewards.
///
/// [TIP-403]: <https://docs.tempo.xyz/protocol/tip403>
/// [TIP-1022]: <https://docs.tempo.xyz/protocol/tip1022>
///
/// Each token lives at a deterministic address with the `0x20C0` prefix.
///
/// The struct fields define the on-chain storage layout; the `#[contract]` macro generates the
/// storage handlers which provide an ergonomic way to interact with the EVM state.
#[contract]
pub struct TIP20Token {
    // RolesAuth
    roles: Mapping<Address, Mapping<B256, bool>>,
    role_admins: Mapping<B256, B256>,

    // TIP20 Metadata
    name: String,
    symbol: String,
    currency: String,
    // TIP-1026: Token Logo URI.
    // Reuses the previously-unused `_domain_separator` slot (always 0 on
    // pre-T5 tokens), which reads as the empty string under Solidity's
    // short-string encoding — matching the spec's "default empty" semantics.
    // Assumes the slot was never written; do not write to it from pre-T5 code.
    logo_uri: String,
    quote_token: Address,
    next_quote_token: Address,
    transfer_policy_id: u64,

    // TIP20 Token
    total_supply: U256,
    balances: Mapping<Address, U256>,
    allowances: Mapping<Address, Mapping<Address, U256>>,
    permit_nonces: Mapping<Address, U256>,
    paused: bool,
    supply_cap: U256,
    // Unused slot, kept for storage layout compatibility
    _salts: Mapping<B256, bool>,

    // TIP20 Rewards
    global_reward_per_token: U256,
    opted_in_supply: u128,
    user_reward_info: Mapping<Address, UserRewardInfo>,
}

/// EIP-712 Permit typehash: keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
pub const PERMIT_TYPEHASH: B256 = B256::new(
    Keccak256::new()
        .update(
            b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)",
        )
        .finalize(),
);

/// EIP-712 domain separator typehash
pub const EIP712_DOMAIN_TYPEHASH: B256 = B256::new(
    Keccak256::new()
        .update(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        )
        .finalize(),
);

/// EIP-712 version hash: keccak256("1")
pub const VERSION_HASH: B256 = B256::new(Keccak256::new().update(b"1").finalize());

/// Role hash for pausing token transfers.
pub const PAUSE_ROLE: B256 = B256::new(Keccak256::new().update(b"PAUSE_ROLE").finalize());
/// Role hash for unpausing token transfers.
pub const UNPAUSE_ROLE: B256 = B256::new(Keccak256::new().update(b"UNPAUSE_ROLE").finalize());
/// Role hash for minting new tokens.
pub const ISSUER_ROLE: B256 = B256::new(Keccak256::new().update(b"ISSUER_ROLE").finalize());
/// Role hash that authorizes burning tokens from blocked accounts.
pub const BURN_BLOCKED_ROLE: B256 =
    B256::new(Keccak256::new().update(b"BURN_BLOCKED_ROLE").finalize());
/// Role hash that authorizes burning tokens from any unprotected account.
pub const BURN_AT_ROLE: B256 = B256::new(Keccak256::new().update(b"BURN_AT_ROLE").finalize());

#[rustfmt::skip]
/// System custody addresses protected from both privileged burn functions at each hardfork.
pub const PROTECTED: &[(TempoHardfork, &[Address])] = &[
    (TempoHardfork::Genesis, &[TIP_FEE_MANAGER_ADDRESS, STABLECOIN_DEX_ADDRESS]),
    (TempoHardfork::T5, &[TIP20_CHANNEL_RESERVE_ADDRESS]),
    (TempoHardfork::T6, &[RECEIVE_POLICY_GUARD_ADDRESS]),
];

impl TIP20Token {
    /// Returns the token name.
    pub fn name(&self) -> Result<String> {
        self.name.read()
    }

    /// Returns the token symbol.
    pub fn symbol(&self) -> Result<String> {
        self.symbol.read()
    }

    /// Returns the token decimals (always 6 for TIP-20).
    pub fn decimals(&self) -> Result<u8> {
        Ok(TIP20_DECIMALS)
    }

    /// Returns the token's currency denomination (e.g. `"USD"`).
    pub fn currency(&self) -> Result<String> {
        self.currency.read()
    }

    /// Returns the logo URI for this token (TIP-1026).
    ///
    /// Returns an empty string if not set.
    pub fn logo_uri(&self) -> Result<String> {
        self.logo_uri.read()
    }

    /// Returns the current total supply.
    pub fn total_supply(&self) -> Result<U256> {
        self.total_supply.read()
    }

    /// Returns the active quote token address used for pricing.
    pub fn quote_token(&self) -> Result<Address> {
        self.quote_token.read()
    }

    /// Returns the pending next quote token address (set but not yet finalized).
    pub fn next_quote_token(&self) -> Result<Address> {
        self.next_quote_token.read()
    }

    /// Returns the maximum mintable supply.
    pub fn supply_cap(&self) -> Result<U256> {
        self.supply_cap.read()
    }

    /// Returns whether the token is currently paused.
    pub fn paused(&self) -> Result<bool> {
        self.paused.read()
    }

    /// Returns the TIP-403 transfer policy ID governing this token's transfers.
    pub fn transfer_policy_id(&self) -> Result<u64> {
        if StorageCtx.spec().is_t9()
            && let Some(policy_id) =
                TIP403Registry::new().registered_token_transfer_policy_id(self.address)?
        {
            return Ok(policy_id);
        }

        self.legacy_transfer_policy_id()
    }

    /// Returns the policy ID stored in the legacy TIP-20 storage slot.
    pub(crate) fn legacy_transfer_policy_id(&self) -> Result<u64> {
        self.transfer_policy_id.read()
    }

    /// Clears the legacy TIP-20 policy slot after its value has moved to TIP-403.
    pub(crate) fn delete_legacy_transfer_policy_id(&mut self) -> Result<()> {
        self.transfer_policy_id.delete()
    }

    /// Returns the PAUSE_ROLE constant
    ///
    /// This role identifier grants permission to pause the token contract.
    /// The role is computed as `keccak256("PAUSE_ROLE")`.
    pub fn pause_role() -> B256 {
        PAUSE_ROLE
    }

    /// Returns the UNPAUSE_ROLE constant
    ///
    /// This role identifier grants permission to unpause the token contract.
    /// The role is computed as `keccak256("UNPAUSE_ROLE")`.
    pub fn unpause_role() -> B256 {
        UNPAUSE_ROLE
    }

    /// Returns the ISSUER_ROLE constant
    ///
    /// This role identifier grants permission to mint and burn tokens.
    /// The role is computed as `keccak256("ISSUER_ROLE")`.
    pub fn issuer_role() -> B256 {
        ISSUER_ROLE
    }

    /// Returns the BURN_BLOCKED_ROLE constant
    ///
    /// This role identifier grants permission to burn tokens from blocked accounts.
    /// The role is computed as `keccak256("BURN_BLOCKED_ROLE")`.
    pub fn burn_blocked_role() -> B256 {
        BURN_BLOCKED_ROLE
    }

    /// Returns the `BURN_AT_ROLE` constant (TIP-1006).
    pub fn burn_at_role() -> B256 {
        BURN_AT_ROLE
    }

    /// Returns the token balance of `account`.
    pub fn balance_of(&self, call: ITIP20::balanceOfCall) -> Result<U256> {
        self.balances[call.account].read()
    }

    /// Returns the remaining allowance that `spender` can transfer on behalf of `owner`.
    pub fn allowance(&self, call: ITIP20::allowanceCall) -> Result<U256> {
        self.allowances[call.owner][call.spender].read()
    }

    /// Updates the [`TIP403Registry`] transfer policy governing this token's transfers.
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold `DEFAULT_ADMIN_ROLE`
    /// - `InvalidTransferPolicyId` — policy does not exist in the [`TIP403Registry`]
    pub fn change_transfer_policy_id(
        &mut self,
        msg_sender: Address,
        call: ITIP20::changeTransferPolicyIdCall,
    ) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;

        // Validate that the policy exists
        if !TIP403Registry::new().policy_exists(ITIP403Registry::policyExistsCall {
            policyId: call.newPolicyId,
        })? {
            return Err(TIP20Error::invalid_transfer_policy_id().into());
        }

        if StorageCtx.spec().is_t9() {
            TIP403Registry::new().set_token_transfer_policy(self.address, call.newPolicyId)?;
        } else {
            self.transfer_policy_id.write(call.newPolicyId)?;
        }

        self.emit_event(TIP20Event::transfer_policy_update(
            msg_sender,
            call.newPolicyId,
        ))
    }

    /// Sets a new supply cap. Must be ≥ current total supply and ≤ [`U128_MAX`].
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold `DEFAULT_ADMIN_ROLE`
    /// - `InvalidSupplyCap` — new cap is below current total supply
    /// - `SupplyCapExceeded` — new cap exceeds [`U128_MAX`]
    pub fn set_supply_cap(
        &mut self,
        msg_sender: Address,
        call: ITIP20::setSupplyCapCall,
    ) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;
        if call.newSupplyCap < self.total_supply()? {
            return Err(TIP20Error::invalid_supply_cap().into());
        }

        if call.newSupplyCap > U128_MAX {
            return Err(TIP20Error::supply_cap_exceeded().into());
        }

        self.supply_cap.write(call.newSupplyCap)?;

        self.emit_event(TIP20Event::supply_cap_update(msg_sender, call.newSupplyCap))
    }

    // ========== TIP-1026: Logo URI ==========

    /// Maximum byte length of a token logo URI (TIP-1026).
    pub const MAX_LOGO_URI_BYTES: usize = 256;

    /// Allowlist of ASCII-case-insensitive URI schemes accepted for [`Self::set_logo_uri`].
    ///
    /// TIP-1026 guarantees that the protocol validates the scheme prefix to make integration easier
    /// and reject obviously dangerous values (e.g. `javascript:`). What the consumer does with the URI
    /// afterwards (rendering, fetching, etc.) is out of scope and remains the consumer's responsibility.
    pub const ALLOWED_LOGO_URI_SCHEMES: &'static [&'static str] =
        &["https", "http", "ipfs", "data"];

    /// Validates a logo URI against the TIP-1026 protocol rules:
    /// - length ≤ [`Self::MAX_LOGO_URI_BYTES`]
    /// - syntactically well-formed URI schemes in [`Self::ALLOWED_LOGO_URI_SCHEMES`].
    ///
    /// Empty strings are accepted unconditionally.
    pub(crate) fn validate_logo_uri(uri: &str) -> Result<()> {
        if uri.len() > Self::MAX_LOGO_URI_BYTES {
            return Err(TIP20Error::logo_uri_too_long().into());
        }
        if !uri.is_empty() && !Self::is_allowed_logo_uri(uri) {
            return Err(TIP20Error::invalid_logo_uri().into());
        }
        Ok(())
    }

    fn is_allowed_logo_uri(uri: &str) -> bool {
        let Some((scheme, _rest)) = uri.split_once(':') else {
            return false;
        };

        let mut bytes = scheme.bytes();
        let Some(first) = bytes.next() else {
            return false;
        };
        if !first.is_ascii_alphabetic() {
            return false;
        }
        if !bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')) {
            return false;
        }

        Self::ALLOWED_LOGO_URI_SCHEMES
            .iter()
            .any(|allowed| scheme.eq_ignore_ascii_case(allowed))
    }

    /// Sets the logo URI for this token (TIP-1026). Empty strings are valid
    /// and clear the URI.
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold `DEFAULT_ADMIN_ROLE`
    /// - `LogoURITooLong` — `bytes(newLogoURI).length > 256`
    /// - `InvalidLogoURI` — `newLogoURI` is non-empty and either has no
    ///   parseable scheme (RFC 3986 §3.1) or its scheme is not in
    ///   [`Self::ALLOWED_LOGO_URI_SCHEMES`]
    pub fn set_logo_uri(
        &mut self,
        msg_sender: Address,
        call: ITIP20::setLogoURICall,
    ) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;
        self.write_logo_uri(msg_sender, call.newLogoURI)
    }

    /// Internal helper: runs [`Self::validate_logo_uri`] (length cap + scheme allowlist), stores the
    /// value, and emits `LogoURIUpdated`.
    ///
    /// **IMPORTANT:** this function performs NO role check. It is the caller's responsibility.
    pub(crate) fn write_logo_uri(&mut self, updater: Address, new_logo_uri: String) -> Result<()> {
        Self::validate_logo_uri(&new_logo_uri)?;

        self.logo_uri.write(new_logo_uri.clone())?;

        self.emit_event(TIP20Event::LogoURIUpdated(ITIP20::LogoURIUpdated {
            updater,
            newLogoURI: new_logo_uri,
        }))
    }

    // ========== End TIP-1026 ==========

    /// Pauses all token transfers.
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold `PAUSE_ROLE`
    pub fn pause(&mut self, msg_sender: Address, _call: ITIP20::pauseCall) -> Result<()> {
        self.check_role(msg_sender, PAUSE_ROLE)?;
        self.paused.write(true)?;

        self.emit_event(TIP20Event::pause_state_update(msg_sender, true))
    }

    /// Unpauses token transfers.
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold `UNPAUSE_ROLE`
    pub fn unpause(&mut self, msg_sender: Address, _call: ITIP20::unpauseCall) -> Result<()> {
        self.check_role(msg_sender, UNPAUSE_ROLE)?;
        self.paused.write(false)?;

        self.emit_event(TIP20Event::pause_state_update(msg_sender, false))
    }

    /// Stages a new quote token. Must be finalized via [`Self::complete_quote_token_update`].
    /// Validates that the candidate is a deployed TIP-20 token (via [`TIP20Factory`]) and, for
    /// USD-denominated tokens, that the candidate is also USD-denominated.
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold `DEFAULT_ADMIN_ROLE`
    /// - `InvalidQuoteToken` — token is pathUSD, candidate is not a deployed TIP-20, or
    ///   USD currency mismatch
    pub fn set_next_quote_token(
        &mut self,
        msg_sender: Address,
        call: ITIP20::setNextQuoteTokenCall,
    ) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;

        if self.address == PATH_USD_ADDRESS {
            return Err(TIP20Error::invalid_quote_token().into());
        }

        // Verify the new quote token is a valid TIP20 token that has been deployed
        // use factory's `is_tip20()` which checks both prefix and counter
        if !TIP20Factory::new().is_tip20(call.newQuoteToken)? {
            return Err(TIP20Error::invalid_quote_token().into());
        }

        // Check if the currency is USD, if so then the quote token's currency MUST also be USD
        let currency = self.currency()?;
        if currency == USD_CURRENCY {
            let quote_token_currency = Self::from_address(call.newQuoteToken)?.currency()?;
            if quote_token_currency != USD_CURRENCY {
                return Err(TIP20Error::invalid_quote_token().into());
            }
        }

        self.next_quote_token.write(call.newQuoteToken)?;

        self.emit_event(TIP20Event::next_quote_token_set(
            msg_sender,
            call.newQuoteToken,
        ))
    }

    /// Finalizes the staged quote token update. Walks the quote-token chain to detect cycles
    /// before committing the change.
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold `DEFAULT_ADMIN_ROLE`
    /// - `InvalidQuoteToken` — update would create a cycle in the quote-token graph
    pub fn complete_quote_token_update(
        &mut self,
        msg_sender: Address,
        _call: ITIP20::completeQuoteTokenUpdateCall,
    ) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;

        let next_quote_token = self.next_quote_token()?;

        // Check that this does not create a loop
        // Loop through quote tokens until we reach the root (pathUSD)
        let mut current = next_quote_token;
        while current != PATH_USD_ADDRESS {
            if current == self.address {
                return Err(TIP20Error::invalid_quote_token().into());
            }

            current = Self::from_address(current)?.quote_token()?;
        }

        // Update the quote token
        self.quote_token.write(next_quote_token)?;

        self.emit_event(TIP20Event::quote_token_update(msg_sender, next_quote_token))
    }

    // Token operations

    /// Mints `amount` tokens to the resolved target `to` address:
    /// - Enforces mint-recipient compliance via [`TIP403Registry`] and validates against supply cap
    /// - Resolves `to` via the [`AddressRegistry`]. If `to` is a virtual address, credits the
    ///   resolved master and emits a two-hop `Transfer` and `Mint(virtual, amount)` events
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold the `ISSUER_ROLE` role
    /// - `ContractPaused` — (+T3) token is paused
    /// - `InvalidRecipient` — (+T3) recipient is zero or a TIP-20 prefix address
    /// - `PolicyForbids` — TIP-403 policy rejects the mint recipient
    /// - `SupplyCapExceeded` — minting would push total supply above the cap
    pub fn mint(&mut self, msg_sender: Address, call: ITIP20::mintCall) -> Result<()> {
        let Some((total_supply, to)) =
            self.validate_mint(msg_sender, call.to, call.amount, B256::ZERO)?
        else {
            return Ok(());
        };

        self._mint(&to, total_supply, call.amount)?;
        self.emit_event(TIP20Event::mint(call.to, call.amount))?;
        if let Some(hop) = to.build_virtual_transfer_event(call.amount) {
            self.emit_event(hop)?;
        }

        Ok(())
    }

    /// Like [`Self::mint`], but attaches a 32-byte memo.
    pub fn mint_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::mintWithMemoCall,
    ) -> Result<()> {
        let Some((total_supply, to)) =
            self.validate_mint(msg_sender, call.to, call.amount, call.memo)?
        else {
            return Ok(());
        };

        self._mint(&to, total_supply, call.amount)?;
        self.emit_event(TIP20Event::transfer_with_memo(
            Address::ZERO,
            call.to,
            call.amount,
            call.memo,
        ))?;
        self.emit_event(TIP20Event::mint(call.to, call.amount))?;
        if let Some(hop) = to.build_virtual_transfer_event(call.amount) {
            self.emit_event(hop)?;
        }
        Ok(())
    }

    /// Internal helper to mint new tokens and update balances.
    pub(crate) fn _mint(&mut self, to: &Recipient, total_supply: U256, amount: U256) -> Result<()> {
        let new_supply = total_supply
            .checked_add(amount)
            .ok_or(TempoPrecompileError::under_overflow())?;

        let supply_cap = self.supply_cap()?;
        if new_supply > supply_cap {
            return Err(TIP20Error::supply_cap_exceeded().into());
        }

        self.handle_rewards_on_mint(to.target, amount)?;

        self.set_total_supply(new_supply)?;
        self.increment_balance(to.target, amount)?;

        self.emit_event(to.build_transfer_event(Address::ZERO, amount))
    }

    /// Burns `amount` from the caller's balance and reduces total supply.
    ///
    /// # Errors
    /// - `ContractPaused` — (+T3) token is paused
    /// - `Unauthorized` — caller does not hold the `ISSUER_ROLE` role
    /// - `InsufficientBalance` — caller balance lower than burn amount
    pub fn burn(&mut self, msg_sender: Address, call: ITIP20::burnCall) -> Result<()> {
        self._burn(msg_sender, call.amount)?;
        self.emit_event(TIP20Event::burn(msg_sender, call.amount))
    }

    /// Like [`Self::burn`], but attaches a 32-byte memo.
    pub fn burn_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::burnWithMemoCall,
    ) -> Result<()> {
        self._burn(msg_sender, call.amount)?;

        self.emit_event(TIP20Event::transfer_with_memo(
            msg_sender,
            Address::ZERO,
            call.amount,
            call.memo,
        ))?;
        self.emit_event(TIP20Event::burn(msg_sender, call.amount))
    }

    /// Burns tokens from addresses blocked by [`TIP403Registry`] policy. Where `owner` refers to
    /// the account with ownership of the funds, either directly, or via the `ReceivePolicyGuard`.
    ///
    /// # Errors
    /// - `ContractPaused` — (+T3) token is paused
    /// - `Unauthorized` — caller does not hold `BURN_BLOCKED_ROLE`
    /// - `PolicyForbids` — target address is not blocked by policy
    /// - `ProtectedAddress` — cannot burn from protected system custody addresses
    pub fn burn_blocked(
        &mut self,
        msg_sender: Address,
        owner: Address,
        amount: U256,
        check_protected: bool,
    ) -> Result<()> {
        let hardfork = self.storage.spec();

        // Validate burner role and (+T3) ensure token is not paused
        if hardfork.is_t3() {
            self.check_not_paused()?;
        }
        self.check_role(msg_sender, BURN_BLOCKED_ROLE)?;

        if check_protected {
            self.check_burn_address(owner)?;
        }

        // Check if the address is blocked from transferring (sender authorization)
        let policy_id = self.transfer_policy_id()?;
        if TIP403Registry::new().is_authorized_as(policy_id, owner, AuthRole::sender())? {
            // Only allow burning from addresses that are blocked from transferring
            return Err(TIP20Error::policy_forbids().into());
        }

        let burn_from = if check_protected {
            owner
        } else {
            RECEIVE_POLICY_GUARD_ADDRESS
        };
        self._transfer(burn_from, &Recipient::direct(Address::ZERO), amount)?;

        let total_supply = self.total_supply()?;
        let new_supply =
            total_supply
                .checked_sub(amount)
                .ok_or(TIP20Error::insufficient_balance(
                    total_supply,
                    amount,
                    self.address,
                ))?;
        self.set_total_supply(new_supply)?;

        self.emit_event(TIP20Event::burn_blocked(owner, amount))
    }

    /// Burns from an unprotected account without checking its transfer policy (TIP-1006).
    ///
    /// Requires `BURN_AT_ROLE` and an unpaused token. When `from` is the transaction origin,
    /// the burn consumes the access key's spending limit even if a bridge is the caller.
    pub fn burn_at(&mut self, msg_sender: Address, call: ITIP20::burnAtCall) -> Result<()> {
        self.check_not_paused()?;
        self.check_role(msg_sender, BURN_AT_ROLE)?;
        self.check_burn_address(call.from)?;
        self.check_and_update_spending_limit(call.from, call.amount)?;

        self._transfer(call.from, &Recipient::direct(Address::ZERO), call.amount)?;
        let total_supply = self.total_supply()?;
        let new_supply =
            total_supply
                .checked_sub(call.amount)
                .ok_or(TIP20Error::insufficient_balance(
                    total_supply,
                    call.amount,
                    self.address,
                ))?;
        self.set_total_supply(new_supply)?;

        self.emit_event(TIP20Event::burn_at(msg_sender, call.from, call.amount))
    }

    /// Rejects pooled custody balances whose destruction would leave outstanding claims unbacked.
    fn check_burn_address(&self, from: Address) -> Result<()> {
        let hardfork = self.storage.spec();
        if PROTECTED
            .iter()
            .any(|(hf, addresses)| hardfork >= *hf && addresses.contains(&from))
            || (hardfork.is_t5() && from == self.address)
            || (hardfork.is_t12() && from.as_slice().starts_with(&Address::ZONE_PORTAL_PREFIX))
        {
            return Err(TIP20Error::protected_address().into());
        }
        Ok(())
    }

    fn _burn(&mut self, msg_sender: Address, amount: U256) -> Result<()> {
        // Validate issuer role and (+T3) ensure token is not paused
        if self.storage.spec().is_t3() {
            self.check_not_paused()?;
        }
        self.check_role(msg_sender, ISSUER_ROLE)?;

        self._transfer(msg_sender, &Recipient::direct(Address::ZERO), amount)?;

        let total_supply = self.total_supply()?;
        let new_supply =
            total_supply
                .checked_sub(amount)
                .ok_or(TIP20Error::insufficient_balance(
                    total_supply,
                    amount,
                    self.address,
                ))?;
        self.set_total_supply(new_supply)
    }

    /// Sets `spender`'s allowance to `amount` for the caller's tokens.
    /// Deducts from the caller's [`AccountKeychain`] spending limit
    /// when the new allowance exceeds the previous one.
    ///
    /// # Errors
    /// - `SpendingLimitExceeded` — new allowance exceeds access key spending limit
    pub fn approve(&mut self, msg_sender: Address, call: ITIP20::approveCall) -> Result<bool> {
        // Check and update spending limits for access keys
        AccountKeychain::new().authorize_approve(
            msg_sender,
            self.address,
            self.get_allowance(msg_sender, call.spender)?,
            call.amount,
        )?;

        // Set the new allowance
        self.set_allowance(msg_sender, call.spender, call.amount)?;

        self.emit_event(TIP20Event::approval(msg_sender, call.spender, call.amount))?;

        Ok(true)
    }

    // EIP-2612 Permit

    /// Returns the current nonce for an address (EIP-2612)
    pub fn nonces(&self, call: ITIP20::noncesCall) -> Result<U256> {
        self.permit_nonces[call.owner].read()
    }

    /// Returns the EIP-712 domain separator, computed dynamically from the token name and chain ID.
    pub fn domain_separator(&self) -> Result<B256> {
        let name = self.name()?;
        let name_hash = self.storage.keccak256(name.as_bytes())?;
        let chain_id = U256::from(self.storage.chain_id());

        let encoded = (
            EIP712_DOMAIN_TYPEHASH,
            name_hash,
            VERSION_HASH,
            chain_id,
            self.address,
        )
            .abi_encode();

        self.storage.keccak256(&encoded)
    }

    /// Sets allowance via a signed [EIP-2612] permit. Validates the ECDSA signature, checks the
    /// deadline, and increments the nonce. Allowed even when the token is paused.
    ///
    /// [EIP-2612]: https://eips.ethereum.org/EIPS/eip-2612
    ///
    /// # Errors
    /// - `PermitExpired` — current timestamp exceeds permit deadline
    /// - `InvalidSignature` — ECDSA recovery failed or recovered signer ≠ owner
    pub fn permit(&mut self, call: ITIP20::permitCall) -> Result<()> {
        // 1. Check deadline
        if self.storage.timestamp() > call.deadline {
            return Err(TIP20Error::permit_expired().into());
        }

        // 2. Construct EIP-712 struct hash
        let nonce = self.permit_nonces[call.owner].read()?;
        let struct_hash = self.storage.keccak256(
            &(
                PERMIT_TYPEHASH,
                call.owner,
                call.spender,
                call.value,
                nonce,
                call.deadline,
            )
                .abi_encode(),
        )?;

        // 3. Construct EIP-712 digest
        let domain_separator = self.domain_separator()?;
        let digest = self.storage.keccak256(
            &[
                &[0x19, 0x01],
                domain_separator.as_slice(),
                struct_hash.as_slice(),
            ]
            .concat(),
        )?;

        // 4. Validate ECDSA signature
        // Only v=27/28 is accepted; v=0/1 is intentionally NOT normalized (see TIP-1004 spec).
        let recovered = self
            .storage
            .recover_signer(digest, call.v, call.r, call.s)?
            .ok_or(TIP20Error::invalid_signature())?;
        if recovered != call.owner {
            return Err(TIP20Error::invalid_signature().into());
        }

        // 5. Increment nonce
        self.permit_nonces[call.owner].write(
            nonce
                .checked_add(U256::from(1))
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // 6. Set allowance
        self.set_allowance(call.owner, call.spender, call.value)?;

        // 7. Emit Approval event
        self.emit_event(TIP20Event::approval(call.owner, call.spender, call.value))
    }

    /// Transfers `amount` tokens from the caller to `to`. Enforces compliance via the
    /// [`TIP403Registry`] and deducts from the caller's [`AccountKeychain`] spending limit.
    ///
    /// # Errors
    /// - `Paused` — token transfers are currently paused
    /// - `InvalidRecipient` — recipient address is zero
    /// - `PolicyForbids` — TIP-403 policy rejects sender or recipient
    /// - `SpendingLimitExceeded` — access key spending limit exceeded
    /// - `InsufficientBalance` — sender balance lower than transfer amount
    pub fn transfer(&mut self, msg_sender: Address, call: ITIP20::transferCall) -> Result<bool> {
        trace!(%msg_sender, ?call, "transferring TIP20");
        let Some(to) =
            self.validate_transfer(None, msg_sender, call.to, call.amount, B256::ZERO)?
        else {
            return Ok(true);
        };

        self._transfer(msg_sender, &to, call.amount)?;
        if let Some(hop) = to.build_virtual_transfer_event(call.amount) {
            self.emit_event(hop)?;
        }

        Ok(true)
    }

    /// Transfers `amount` on behalf of `from` using the caller's allowance.
    /// Enforces compliance via the [`TIP403Registry`].
    ///
    /// # Errors
    /// - `Paused` — token transfers are currently paused
    /// - `InvalidRecipient` — recipient address is zero
    /// - `PolicyForbids` — TIP-403 policy rejects sender or recipient
    /// - `InsufficientAllowance` — caller allowance lower than transfer amount
    /// - `InsufficientBalance` — `from` balance lower than transfer amount
    pub fn transfer_from(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferFromCall,
    ) -> Result<bool> {
        let Some(to) = self.validate_transfer(
            Some(msg_sender),
            call.from,
            call.to,
            call.amount,
            B256::ZERO,
        )?
        else {
            return Ok(true);
        };

        self._transfer(call.from, &to, call.amount)?;
        if let Some(hop) = to.build_virtual_transfer_event(call.amount) {
            self.emit_event(hop)?;
        }

        Ok(true)
    }

    /// Like [`Self::transfer_from`], but attaches a 32-byte memo.
    pub fn transfer_from_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferFromWithMemoCall,
    ) -> Result<bool> {
        let Some(to) =
            self.validate_transfer(Some(msg_sender), call.from, call.to, call.amount, call.memo)?
        else {
            return Ok(true);
        };

        self._transfer(call.from, &to, call.amount)?;
        self.emit_event(TIP20Event::transfer_with_memo(
            call.from,
            call.to,
            call.amount,
            call.memo,
        ))?;
        if let Some(hop) = to.build_virtual_transfer_event(call.amount) {
            self.emit_event(hop)?;
        }
        Ok(true)
    }

    /// Transfers `amount` from `from` to `to` without checking allowances. For use by precompiles
    /// on the [`crate::address_registry::IMPLICIT_APPROVAL_LIST`] only — not exposed via ABI.
    /// Enforces compliance via the [`TIP403Registry`] and [`AccountKeychain`].
    ///
    /// `caller` is the address of the precompile invoking this function. Starting at
    /// `TempoHardfork::T5` (TIP-1035), the call returns `Unauthorized` unless `caller` is on the
    /// Implicit Approval List. Pre-T5, `caller` is unchecked (preserves pre-TIP-1035 behavior of
    /// the existing internal-only caller, `TipFeeManager`).
    ///
    /// Callers are also expected to pull only from the current `msg.sender`; this is a security
    /// guideline of TIP-1035 enforced at the call site, not by this function.
    ///
    /// # Errors
    /// - `Unauthorized` — `caller` is not on the Implicit Approval List (T5+)
    /// - `Paused` — token transfers are currently paused
    /// - `InvalidRecipient` — recipient address is zero
    /// - `PolicyForbids` — TIP-403 policy rejects sender or recipient
    /// - `SpendingLimitExceeded` — access key spending limit exceeded
    /// - `InsufficientBalance` — `from` balance lower than transfer amount
    pub fn system_transfer_from(
        &mut self,
        caller: Address,
        from: Address,
        amount: U256,
    ) -> Result<bool> {
        // [TIP-1035] List gating: at T5+, only listed precompiles may invoke this entrypoint.
        let spec = self.storage.spec();
        if spec.is_t5() && !crate::address_registry::is_implicitly_approved(caller, spec) {
            return Err(TIP20Error::unauthorized().into());
        }

        let Some(to) = self.validate_transfer(None, from, caller, amount, B256::ZERO)? else {
            return Ok(true);
        };

        self._transfer(from, &to, amount)?;
        if let Some(hop) = to.build_virtual_transfer_event(amount) {
            self.emit_event(hop)?;
        }

        Ok(true)
    }

    /// Moves channel-reserve custody after the reserve applies operation-specific TIP-403 rules.
    ///
    /// This is an internal TIP-1034 integration, not an ABI entrypoint. At least one physical
    /// endpoint must be the canonical channel reserve. The reserve checks the logical payer-payee
    /// path before funding and capture, and derives refunds from authenticated channel state.
    ///
    /// `receive_policy_sender` is the sender presented to TIP-1028. It may differ from the physical
    /// balance owner when reserve custody pays a channel's payee. Unlike ordinary TIP-20 transfers,
    /// channel custody movements revert when TIP-1028 rejects delivery because channel accounting
    /// cannot represent a pending guarded payment.
    pub(crate) fn channel_reserve_transfer(
        &mut self,
        from: Address,
        to: Recipient,
        amount: U256,
        receive_policy_sender: Address,
    ) -> Result<()> {
        if from != TIP20_CHANNEL_RESERVE_ADDRESS
            && to.original_address() != TIP20_CHANNEL_RESERVE_ADDRESS
        {
            return Err(TIP20Error::unauthorized().into());
        }

        self.check_not_paused()?;
        to.validate()?;
        self.check_and_update_spending_limit(from, amount)?;

        if to.target == RECEIVE_POLICY_GUARD_ADDRESS {
            return Err(ReceivePolicyGuardError::address_reserved().into());
        }
        self.ensure_receive_policy_authorized(receive_policy_sender, to.target)?;

        self._transfer(from, &to, amount)?;
        if let Some(hop) = to.build_virtual_transfer_event(amount) {
            self.emit_event(hop)?;
        }

        Ok(())
    }

    /// Debits `spender`'s allowance on `owner`. No-op when unlimited.
    fn consume_allowance(&mut self, owner: Address, spender: Address, amount: U256) -> Result<()> {
        let allowed = self.get_allowance(owner, spender)?;
        if amount > allowed {
            return Err(TIP20Error::insufficient_allowance().into());
        }

        if allowed != U256::MAX {
            let new_allowance = allowed
                .checked_sub(amount)
                .ok_or(TIP20Error::insufficient_allowance())?;
            self.set_allowance(owner, spender, new_allowance)?;
        }
        Ok(())
    }

    /// Like [`Self::transfer`], but attaches a 32-byte memo.
    pub fn transfer_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferWithMemoCall,
    ) -> Result<()> {
        let Some(to) = self.validate_transfer(None, msg_sender, call.to, call.amount, call.memo)?
        else {
            return Ok(());
        };

        self._transfer(msg_sender, &to, call.amount)?;
        self.emit_event(TIP20Event::transfer_with_memo(
            msg_sender,
            call.to,
            call.amount,
            call.memo,
        ))?;
        if let Some(hop) = to.build_virtual_transfer_event(call.amount) {
            self.emit_event(hop)?;
        }
        Ok(())
    }
}

// Utility functions
impl TIP20Token {
    /// Creates a `TIP20Token` handle from a raw address.
    ///
    /// # Errors
    /// - `InvalidToken` — address does not carry the `0x20C0` TIP-20 prefix
    pub fn from_address(address: Address) -> Result<Self> {
        if !address.is_tip20() {
            return Err(TIP20Error::invalid_token().into());
        }
        Ok(Self::__new(address))
    }

    /// Creates a TIP20Token without validating the prefix.
    ///
    /// # Safety
    /// Caller must ensure `is_tip20_prefix(address)` returns true.
    #[inline]
    pub fn from_address_unchecked(address: Address) -> Self {
        debug_assert!(address.is_tip20(), "address must have TIP20 prefix");
        Self::__new(address)
    }

    /// Initializes the TIP-20 token precompile with metadata, quote token, supply cap, and
    /// default admin role. Called once by [`TIP20Factory`] during token creation.
    pub fn initialize(
        &mut self,
        msg_sender: Address,
        name: &str,
        symbol: &str,
        currency: &str,
        quote_token: Address,
        admin: Address,
    ) -> Result<()> {
        trace!(%name, address=%self.address, "Initializing token");

        // must ensure the account is not empty, by setting some code
        self.__initialize()?;

        self.name.write(name.to_string())?;
        self.symbol.write(symbol.to_string())?;
        self.currency.write(currency.to_string())?;

        self.quote_token.write(quote_token)?;
        // Initialize nextQuoteToken to the same value as quoteToken
        self.next_quote_token.write(quote_token)?;

        // Set default values
        self.supply_cap.write(U128_MAX)?;
        if StorageCtx.spec().is_t9() {
            TIP403Registry::new().set_token_transfer_policy(self.address, ALLOW_ALL_POLICY_ID)?;
        } else {
            self.transfer_policy_id.write(ALLOW_ALL_POLICY_ID)?;
        }

        // Initialize roles system and grant admin role
        self.initialize_roles()?;
        self.grant_default_admin(msg_sender, admin)
    }

    /// Returns the token's name, symbol and currency.
    pub fn metadata(&self) -> Result<Tip20TokenMetadata> {
        Ok(Tip20TokenMetadata {
            name: self.name()?,
            symbol: self.symbol()?,
            currency: self.currency()?,
        })
    }

    fn get_balance(&self, account: Address) -> Result<U256> {
        self.balances[account].read()
    }

    fn set_balance(&mut self, account: Address, amount: U256) -> Result<()> {
        self.balances[account].write(amount)
    }

    pub fn increment_balance(&mut self, account: Address, amount: U256) -> Result<()> {
        self.balances[account].sinc(amount).map_err(|err| {
            if err == TempoPrecompileError::under_overflow() {
                TIP20Error::supply_cap_exceeded().into()
            } else {
                err
            }
        })
    }

    pub fn decrement_balance(&mut self, account: Address, amount: U256) -> Result<()> {
        self.balances[account]
            .sdec(amount)
            .map_err(|err| match err {
                TempoPrecompileError::StorageDeltaUnderflow(current) => {
                    TIP20Error::insufficient_balance(current, amount, self.address).into()
                }
                err => err,
            })
    }

    fn get_allowance(&self, owner: Address, spender: Address) -> Result<U256> {
        self.allowances[owner][spender].read()
    }

    fn set_allowance(&mut self, owner: Address, spender: Address, amount: U256) -> Result<()> {
        self.allowances[owner][spender].write(amount)
    }

    fn set_total_supply(&mut self, amount: U256) -> Result<()> {
        self.total_supply.write(amount)
    }

    pub fn check_not_paused(&self) -> Result<()> {
        if self.paused()? {
            return Err(TIP20Error::contract_paused().into());
        }
        Ok(())
    }

    /// Resolves `to`, checks pause state and recipient validity, ensures TIP-403 transfer
    /// authorization, and runs the caller-specific spend check. Additionally (+T6) applies
    /// TIP-1028 address-level receive policies.
    ///
    /// Updates the sender's [`AccountKeychain`] spending limit for direct transfers, and
    /// consumes allowance for `transfer_from` style calls.
    ///
    /// Returns `Some(to)` when the caller should perform the normal transfer.
    /// Returns `None` when funds were blocked, and the caller should return immediately.
    fn validate_transfer(
        &mut self,
        spender: Option<Address>,
        from: Address,
        to: Address,
        amount: U256,
        memo: B256,
    ) -> Result<Option<Recipient>> {
        let to = Recipient::resolve(to)?;
        self.check_not_paused()?;
        to.validate()?;
        self.ensure_transfer_authorized(from, to.target)?;

        if let Some(spender) = spender {
            self.consume_allowance(from, spender, amount)?;
        } else {
            self.check_and_update_spending_limit(from, amount)?;
        }

        if self.validate_inbound_or_block(from, &to, amount, None, memo)? {
            return Ok(None);
        }

        Ok(Some(to))
    }

    /// Resolves `to`, checks the issuer role, and ensures TIP-403 mint-recipient authorization.
    /// Additionally (+T3) checks pause state and validates the effective recipient; also
    /// (+T6) applies TIP-1028 address-level receive policies.
    ///
    /// Returns `Some(to)` when the caller should proceed with the regular mint.
    /// Returns `None` when funds were minted and blocked, and the caller should return immediately.
    fn validate_mint(
        &mut self,
        msg_sender: Address,
        to: Address,
        amount: U256,
        memo: B256,
    ) -> Result<Option<(U256, Recipient)>> {
        let to = Recipient::resolve(to)?;
        self.check_role(msg_sender, ISSUER_ROLE)?;
        let total_supply = self.total_supply()?;

        if self.storage.spec().is_t3() {
            self.check_not_paused()?;
            to.validate()?;
        }

        // Check if the resolved target address is authorized to receive minted tokens
        if !TIP403Registry::new().is_authorized_as(
            self.transfer_policy_id()?,
            to.target,
            AuthRole::mint_recipient(),
        )? {
            return Err(TIP20Error::policy_forbids().into());
        }

        if self.validate_inbound_or_block(msg_sender, &to, amount, Some(total_supply), memo)? {
            return Ok(None);
        }

        Ok(Some((total_supply, to)))
    }

    /// Check whether a transfer is authorized by the token's [`TIP403Registry`] policy.
    /// [TIP-1015]: For T2+, uses directional sender/recipient checks.
    ///
    /// [TIP-1015]: <https://docs.tempo.xyz/protocol/tips/tip-1015>
    pub fn is_transfer_authorized(&self, from: Address, to: Address) -> Result<bool> {
        let policy_id = self.transfer_policy_id()?;
        let registry = TIP403Registry::new();

        // (spec: +T2) short-circuit and skip recipient check if sender fails
        let sender_auth = registry.is_authorized_as(policy_id, from, AuthRole::sender())?;
        if self.storage.spec().is_t2() && !sender_auth {
            return Ok(false);
        }
        let recipient_auth = registry.is_authorized_as(policy_id, to, AuthRole::recipient())?;
        Ok(sender_auth && recipient_auth)
    }

    /// Ensures the transfer is authorized by the token's [`TIP403Registry`] policy.
    ///
    /// # Errors
    /// - `PolicyForbids` — sender or recipient is not authorized by the active transfer policy
    pub fn ensure_transfer_authorized(&self, from: Address, to: Address) -> Result<()> {
        if !self.is_transfer_authorized(from, to)? {
            return Err(TIP20Error::policy_forbids().into());
        }

        Ok(())
    }

    /// Ensures `receiver` currently accepts this token from `sender` under TIP-1028.
    ///
    /// Receive policies remain mutable, so a later policy change can still block delivery.
    pub(crate) fn ensure_receive_policy_authorized(
        &self,
        sender: Address,
        receiver: Address,
    ) -> Result<()> {
        if TIP403Registry::new()
            .validate_receive_policy(self.address, sender, receiver)?
            .is_some()
        {
            return Err(TIP20Error::policy_forbids().into());
        }

        Ok(())
    }

    /// Check whether users are authorized by the token's [`TIP403Registry`] policy for the given
    /// roles.
    ///
    /// # Errors
    /// - `PolicyForbids` — a user is not authorized for the requested role by the active transfer policy
    pub fn ensure_authorized_as(&self, user_auth: &[(Address, AuthRole)]) -> Result<()> {
        let policy_id = self.transfer_policy_id()?;
        let registry = TIP403Registry::new();
        for &(user, role) in user_auth {
            if !registry.is_authorized_as(policy_id, user, role)? {
                return Err(TIP20Error::policy_forbids().into());
            }
        }
        Ok(())
    }

    /// Checks and deducts `amount` from the caller's [`AccountKeychain`] spending limit.
    ///
    /// # Errors
    /// - `SpendingLimitExceeded` — access key spending limit exceeded
    pub fn check_and_update_spending_limit(&mut self, from: Address, amount: U256) -> Result<()> {
        AccountKeychain::new().authorize_transfer(from, self.address, amount)
    }

    /// Core transfer: debits `from`, credits `to.target`, emits `Transfer(from, event_addr, amount)`.
    ///
    /// For virtual recipients the event address is the virtual alias; the balance update always
    /// targets `to.target` (the resolved master).
    pub fn _transfer(&mut self, from: Address, to: &Recipient, amount: U256) -> Result<()> {
        let from_balance = if !self.storage.spec().is_t8() {
            let from_balance = self.get_balance(from)?;
            if amount > from_balance {
                return Err(
                    TIP20Error::insufficient_balance(from_balance, amount, self.address).into(),
                );
            }
            Some(from_balance)
        } else {
            None
        };

        self.handle_rewards_on_transfer(from, to.target, amount)?;

        // Adjust balances
        //
        // We can't just use `decrement_balance` in both pre- and post-T8 codepaths, because `decrement_balance`
        // charges gas for balance SLOAD that we already do above for pre-T8.
        if let Some(from_balance) = from_balance {
            // pre-T8 path
            let new_from_balance = from_balance
                .checked_sub(amount)
                .ok_or(TempoPrecompileError::under_overflow())?;

            self.set_balance(from, new_from_balance)?;
        } else {
            // post-T8 path
            self.decrement_balance(from, amount)?;
        }

        if to.target != Address::ZERO {
            self.increment_balance(to.target, amount)?;
        }

        self.emit_event(to.build_transfer_event(from, amount))
    }

    /// Validates the receive policy of `to.target`. If blocked, moves the funds into the guard
    /// account and stores a claim receipt; returns `true`. Returns `false` when the inbound is
    /// authorized and the caller should proceed with the normal transfer or mint.
    pub(crate) fn validate_inbound_or_block(
        &mut self,
        originator: Address,
        to: &Recipient,
        amount: U256,
        mint_total_supply: Option<U256>,
        memo: B256,
    ) -> Result<bool> {
        if !self.storage.spec().is_t6() {
            return Ok(false);
        }
        if to.target == RECEIVE_POLICY_GUARD_ADDRESS {
            return Err(ReceivePolicyGuardError::address_reserved().into());
        }

        let token = self.address;
        let Some((reason, recovery)) =
            TIP403Registry::new().check_receive_policy(token, originator, to.target)?
        else {
            return Ok(false);
        };

        let guard = Recipient::direct(RECEIVE_POLICY_GUARD_ADDRESS);
        let kind = if let Some(total_supply) = mint_total_supply {
            self._mint(&guard, total_supply, amount)?;
            self.emit_event(TIP20Event::mint(guard.target, amount))?;
            InboundKind::MINT
        } else {
            self._transfer(originator, &guard, amount)?;
            InboundKind::TRANSFER
        };
        ReceivePolicyGuard::new()
            .store_blocked(token, originator, to, recovery, amount, reason, kind, memo)?;

        Ok(true)
    }

    /// Releases guarded funds to `to`. Resumes skip policy checks. Reroutes
    /// revalidate the transfer and receive policies and meter the spending limit.
    pub(crate) fn release_blocked_funds(
        &mut self,
        originator: Address,
        receiver: Address,
        to: Address,
        amount: U256,
        recovery_mode: RecoveryMode,
        recovery_auth: Address,
    ) -> Result<()> {
        debug_assert!(
            to != RECEIVE_POLICY_GUARD_ADDRESS,
            "checked in ReceivePolicyGuard::claim"
        );

        self.check_not_paused()?;
        let destination = Recipient::resolve(to)?;
        destination.validate()?;
        if recovery_mode.is_reroute(to, receiver) {
            let policy_subject = recovery_mode.policy_subject(originator, receiver);
            self.ensure_transfer_authorized(policy_subject, destination.target)?;
            if TIP403Registry::new()
                .validate_receive_policy(self.address, policy_subject, destination.target)?
                .is_some()
            {
                return Err(TIP20Error::policy_forbids().into());
            }
            if let Some(addr) = recovery_mode.spending_account(recovery_auth) {
                self.check_and_update_spending_limit(addr, amount)?;
            }
        } else {
            self.ensure_authorized_as(&[(destination.target, AuthRole::recipient())])?;
        }

        self._transfer(RECEIVE_POLICY_GUARD_ADDRESS, &destination, amount)?;
        if let Some(hop) = destination.build_virtual_transfer_event(amount) {
            self.emit_event(hop)?;
        }
        Ok(())
    }

    /// Transfers fee tokens from `from` to the fee manager before transaction execution.
    /// Respects the token's pause state and deducts from the [`AccountKeychain`] spending limit.
    ///
    /// # Errors
    /// - `Paused` — token transfers are currently paused
    /// - `InsufficientBalance` — sender balance lower than fee amount
    /// - `SpendingLimitExceeded` — access key spending limit exceeded
    pub fn transfer_fee_pre_tx(&mut self, from: Address, amount: U256) -> Result<()> {
        // This function respects the token's pause state and will revert if the token is paused.
        // transfer_fee_post_tx is intentionally allowed to execute even when the token is paused.
        // This ensures that a transaction which pauses the token can still complete successfully and receive its fee refund.
        // Apart from this specific refund transfer, no other token transfers can occur after a pause event.
        self.check_not_paused()?;
        self.check_and_update_spending_limit(from, amount)?;

        // Update rewards for the sender and get their reward recipient
        let from_reward_recipient = self.update_rewards(from)?;

        // If user is opted into rewards, decrease opted-in supply
        if from_reward_recipient != Address::ZERO {
            let opted_in_supply = U256::from(self.get_opted_in_supply()?)
                .checked_sub(amount)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_opted_in_supply(
                opted_in_supply
                    .try_into()
                    .map_err(|_| TempoPrecompileError::under_overflow())?,
            )?;
        }

        self.decrement_balance(from, amount)?;
        self.increment_balance(TIP_FEE_MANAGER_ADDRESS, amount)?;

        Ok(())
    }

    /// Refunds unused fee tokens from the fee manager back to `to` and emits a transfer event for
    /// the actual gas spent. Intentionally allowed when paused so that a pause transaction can
    /// still receive its fee refund. On T1C+, also restores the [`AccountKeychain`] spending limit
    /// by the refund amount.
    pub fn transfer_fee_post_tx(
        &mut self,
        to: Address,
        refund: U256,
        actual_spending: U256,
    ) -> Result<()> {
        self.emit_event(TIP20Event::transfer(
            to,
            TIP_FEE_MANAGER_ADDRESS,
            actual_spending,
        ))?;

        // Exit early if there is no refund
        if refund.is_zero() {
            return Ok(());
        }

        if self.storage.spec().is_t1c() {
            AccountKeychain::new().refund_spending_limit(to, self.address, refund)?;
        }

        // Update rewards for the recipient and get their reward recipient
        let to_reward_recipient = self.update_rewards(to)?;

        // If user is opted into rewards, increase opted-in supply by refund amount
        if to_reward_recipient != Address::ZERO {
            let opted_in_supply = U256::from(self.get_opted_in_supply()?)
                .checked_add(refund)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_opted_in_supply(
                opted_in_supply
                    .try_into()
                    .map_err(|_| TempoPrecompileError::under_overflow())?,
            )?;
        }

        self.decrement_balance(TIP_FEE_MANAGER_ADDRESS, refund)?;
        self.increment_balance(to, refund)?;

        Ok(())
    }
}

/// Descriptive TIP-20 token metadata, written once when the token is initialized.
///
/// `decimals` is omitted because all TIP-20 tokens use a fixed decimal count.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Tip20TokenMetadata {
    pub name: String,
    pub symbol: String,
    pub currency: String,
}

/// Resolved transfer recipient for [TIP-1022] virtual address support.
///
/// `target` is always the effective (resolved) address where the balance is credited. For virtual
/// recipients, `virtual_addr` carries the original virtual address for event emission.
///
/// [TIP-1022]: <https://docs.tempo.xyz/protocol/tip1022>
#[derive(Debug, PartialEq)]
pub struct Recipient {
    /// The effective (resolved) address where the balance is credited.
    pub(crate) target: Address,
    /// The virtual address, if registered.
    pub(crate) virtual_addr: Option<Address>,
}

impl Recipient {
    /// Creates a [`Recipient`] with no virtual indirection.
    #[inline]
    pub fn direct(addr: Address) -> Self {
        Self {
            target: addr,
            virtual_addr: None,
        }
    }

    /// Resolves a recipient via the [`AddressRegistry`].
    ///
    /// If `addr` is a virtual address its registered master is looked up and stored in `target`,
    /// with the original virtual address preserved in `virtual_addr`.
    pub(crate) fn resolve(addr: Address) -> Result<Self> {
        let effective = AddressRegistry::new().resolve_recipient(addr)?;
        Ok(if effective == addr {
            Self::direct(addr)
        } else {
            Self {
                target: effective,
                virtual_addr: Some(addr),
            }
        })
    }

    /// Returns the original recipient address used by the transfer.
    fn original_address(&self) -> Address {
        self.virtual_addr.unwrap_or(self.target)
    }

    /// Validates that the recipient is not:
    /// - the zero address (preventing accidental burns)
    /// - an address with the TIP-20 prefix (preventing transfers to token contracts)
    pub(crate) fn validate(&self) -> Result<()> {
        if self.target.is_zero() || self.target.is_tip20() {
            return Err(TIP20Error::invalid_recipient().into());
        }
        Ok(())
    }

    /// Builds the primary `Transfer(from, to, amount)` event.
    ///
    /// For virtual recipients `to` is the virtual address (first hop); for regular
    /// recipients this is the only `Transfer` event needed.
    pub(crate) fn build_transfer_event(&self, from: Address, amount: U256) -> TIP20Event {
        TIP20Event::transfer(from, self.original_address(), amount)
    }

    /// Builds the forwarding `Transfer(virtual, master, amount)` event for virtual recipients.
    /// Returns `None` for non-virtual recipients.
    pub(crate) fn build_virtual_transfer_event(&self, amount: U256) -> Option<TIP20Event> {
        self.virtual_addr
            .map(|virtual_addr| TIP20Event::transfer(virtual_addr, self.target, amount))
    }
}




