//! [TIP-1028] ReceivePolicyGuard precompile for blocked inbound TIP-20 transfers and mints.

pub mod dispatch;

pub use tempo_contracts::precompiles::IReceivePolicyGuard::{self, InboundKind};
use tempo_contracts::precompiles::{
    IReceivePolicyGuard::ClaimReceiptV1, ITIP403Registry::BlockedReason, ReceivePolicyGuardError,
};

use crate::{
    RECEIVE_POLICY_GUARD_ADDRESS,
    address_registry::AddressRegistry,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
    tip20::{Recipient, TIP20Token},
};
use alloy::{
    primitives::{Address, B256, Bytes, U256},
    sol_types::SolValue,
};
use tempo_precompiles_macros::{Storable, contract};
use tempo_primitives::TempoAddressExt;

/// Version tag for the v1 [`IReceivePolicyGuard::ClaimReceiptV1`] layout.
pub const BLOCKED_RECEIPT_VERSION: u8 = 1;

/// Recovery-authority sentinel: originator/sender is authorized to claim (`address(0)`).
pub const RECOVERY_ORIGINATOR: Address = Address::ZERO;

/// TIP-1028 precompile holding blocked inbound transfers and mints until claimed.
#[contract(addr = RECEIVE_POLICY_GUARD_ADDRESS)]
pub struct ReceivePolicyGuard {
    nonce: u64,
    balances: Mapping<B256, U256>,
}

impl ReceivePolicyGuard {
    /// One-time storage initialization.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Returns the unclaimed amount for a receipt, or zero if unknown or already claimed.
    pub fn balance_of(&self, receipt: Bytes) -> Result<U256> {
        let receipt = ClaimReceiptV1::try_from(receipt)?;
        self.balances[self.receipt_key(&receipt)?].read()
    }

    /// Records a blocked inbound transfer or mint and emits `TransferBlocked` event.
    /// Caller must send the funds into this address, which are claimable with a valid receipt.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn store_blocked(
        &mut self,
        token: Address,
        originator: Address,
        to: &Recipient,
        recovery_address: Address,
        amount: U256,
        blocked_reason: BlockedReason,
        kind: InboundKind,
        memo: B256,
    ) -> Result<(u64, u64)> {
        debug_assert!(
            token.is_tip20(),
            "ReceivePolicyGuard only accepts TIP20 tokens"
        );

        let is_invalid_reason = match blocked_reason {
            BlockedReason::RECEIVE_POLICY | BlockedReason::TOKEN_FILTER => false,
            BlockedReason::NONE | BlockedReason::__Invalid => true,
        };
        if is_invalid_reason || matches!(kind, InboundKind::__Invalid) {
            return Err(ReceivePolicyGuardError::invalid_receipt().into());
        }

        let receiver = to.target;
        let recipient = to.virtual_addr.unwrap_or(to.target);

        let blocked_nonce = self.next_receipt_nonce()?;
        let blocked_at = self.storage.timestamp().saturating_to::<u64>();
        let receipt = IReceivePolicyGuard::ClaimReceiptV1::new(
            token,
            recovery_address,
            originator,
            recipient,
            blocked_at,
            blocked_nonce,
            blocked_reason as u8,
            kind,
            memo,
        );
        let key = self.receipt_key(&receipt)?;
        self.balances[key].write(amount)?;

        self.emit_event(receipt.blocked_event(receiver, amount))?;
        Ok((blocked_nonce, blocked_at))
    }

    /// Given a valid receipt, releases blocked funds to the authorized receiver.
    pub fn claim(&mut self, msg_sender: Address, to: Address, receipt: Bytes) -> Result<()> {
        if to == RECEIVE_POLICY_GUARD_ADDRESS {
            return Err(ReceivePolicyGuardError::invalid_claim_address().into());
        }

        let (receipt, receiver, recovery_mode) = resolve_receipt(receipt)?;
        let recovery_authority = recovery_mode.authority(&receipt);
        if recovery_authority != msg_sender {
            return Err(ReceivePolicyGuardError::unauthorized_claimer().into());
        };

        let key = self.receipt_key(&receipt)?;
        let amount = self.balances[key].read()?;
        if amount.is_zero() {
            return Err(ReceivePolicyGuardError::invalid_receipt().into());
        }

        self.balances[key].write(U256::ZERO)?;

        TIP20Token::from_address(receipt.token)?.release_blocked_funds(
            receipt.originator,
            receiver,
            to,
            amount,
            recovery_mode,
            recovery_authority,
        )?;

        self.emit_event(receipt.claimed_event(receiver, msg_sender, to, amount))
    }

    /// Burns the blocked funds for one receipt.
    ///
    /// Lets token issuers use `burnBlocked` for receipt-backed funds without burning directly from
    /// the `ReceivePolicyGuard`.
    pub fn burn_blocked_receipt(&mut self, msg_sender: Address, receipt: Bytes) -> Result<()> {
        let (receipt, receiver, recovery_mode) = resolve_receipt(receipt)?;

        let key = self.receipt_key(&receipt)?;
        let amount = self.balances[key].read()?;
        if amount.is_zero() {
            return Err(ReceivePolicyGuardError::invalid_receipt().into());
        }

        // Burn from the account with ownership of the funds.
        let owner = recovery_mode.policy_subject(receipt.originator, receiver);
        TIP20Token::from_address(receipt.token)?.burn_blocked(msg_sender, owner, amount, false)?;
        self.balances[key].write(U256::ZERO)?;

        self.emit_event(receipt.burned_event(receiver, msg_sender, amount))
    }

    /// Allocates the next nonzero receipt nonce.
    fn next_receipt_nonce(&mut self) -> Result<u64> {
        let nonce = self.nonce.read()?.max(1);
        self.nonce.write(
            nonce
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;
        Ok(nonce)
    }

    /// Content hash over every receipt field. Any mutation yields a different empty slot.
    fn receipt_key(&self, receipt: &IReceivePolicyGuard::ClaimReceiptV1) -> Result<B256> {
        self.storage.keccak256(receipt.abi_encode().as_ref())
    }
}

/// Recovery authority for blocked inbound funds.
#[derive(Debug, Clone, Copy, Default, Storable, PartialEq)]
#[repr(u8)]
pub(crate) enum RecoveryMode {
    #[default]
    Originator,
    Receiver,
    ThirdParty,
}

impl RecoveryMode {
    /// Encodes a configured recovery authority into a mode and stored authority value.
    pub(crate) fn encode(authority: Address, msg_sender: Address) -> (Self, Address) {
        if authority == RECOVERY_ORIGINATOR {
            (Self::Originator, Address::ZERO)
        } else if authority == msg_sender {
            (Self::Receiver, Address::ZERO)
        } else {
            (Self::ThirdParty, authority)
        }
    }

    /// Resolves the recovery mode for a receipt and resolved receiver.
    pub(crate) fn from(receipt: &ClaimReceiptV1, receiver: Address) -> Self {
        if receipt.recoveryAuthority == RECOVERY_ORIGINATOR {
            Self::Originator
        } else if receipt.recoveryAuthority == receiver {
            Self::Receiver
        } else {
            Self::ThirdParty
        }
    }

    /// Returns the authorized claimer address for this mode.
    pub(crate) fn authority(self, receipt: &ClaimReceiptV1) -> Address {
        match self {
            Self::Originator => receipt.originator,
            Self::Receiver | Self::ThirdParty => receipt.recoveryAuthority,
        }
    }

    /// Returns the address of the account who has effective ownership of the blocked funds.
    pub(crate) fn policy_subject(self, originator: Address, receiver: Address) -> Address {
        match self {
            Self::Originator => originator,
            Self::Receiver | Self::ThirdParty => receiver,
        }
    }

    /// Returns whether a claim is a reroute under TIP-1028.
    /// Originator-authorized claims are always reroutes; non-originator recovery claims resume
    /// only when claiming to the receiver.
    pub(crate) fn is_reroute(self, to: Address, receiver: Address) -> bool {
        match self {
            Self::Originator => true,
            Self::Receiver | Self::ThirdParty => to != receiver,
        }
    }

    /// Returns the account charged for access-key spending limits, if any.
    pub(crate) fn spending_account(self, recovery_authority: Address) -> Option<Address> {
        match self {
            Self::Originator | Self::Receiver => Some(recovery_authority),
            Self::ThirdParty => None,
        }
    }
}

fn resolve_receipt(bytes: Bytes) -> Result<(ClaimReceiptV1, Address, RecoveryMode)> {
    let receipt = ClaimReceiptV1::try_from(bytes)?;
    let receiver = AddressRegistry::new()
        .resolve_recipient(receipt.recipient)
        .map_err(|_| ReceivePolicyGuardError::invalid_claim_address())?;
    let recovery_mode = RecoveryMode::from(&receipt, receiver);

    Ok((receipt, receiver, recovery_mode))
}


