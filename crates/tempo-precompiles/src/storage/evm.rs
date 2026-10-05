use crate::{
    error::TempoPrecompileError,
    storage::{PrecompileStorageProvider, StorageActions, actions::StorageAction},
    storage_credits::{NonCreditableSlots, sstore_storage_credits},
};
use alloy::primitives::{Address, B256, Log, LogData, U256};
use alloy_evm::EvmInternals;
use bitflags::bitflags;
use revm::{
    context::{CfgEnv, journaled_state::JournalCheckpoint},
    context_interface::cfg::{GasParams, gas},
    interpreter::{SStoreResult, StateLoad, gas::GasTracker},
    state::{AccountInfo, Bytecode},
};
use std::{cell::RefCell, rc::Rc};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::TempoBlockEnv;

/// Production [`PrecompileStorageProvider`] backed by the live EVM journal.
///
/// Wraps `EvmInternals` and tracks gas consumption for storage operations.
pub struct EvmPrecompileStorageProvider<'a> {
    internals: EvmInternals<'a>,
    gas_tracker: GasTracker,
    spec: TempoHardfork,
    amsterdam_eip8037_enabled: bool,
    is_static: bool,
    gas_params: GasParams,
    tip1060_storage_credits_enabled: bool,
    tip1060_storage_credit_minting_enabled: bool,
    non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    /// Debug-only LIFO checkpoint validator. See [`Self::assert_lifo`].
    #[cfg(debug_assertions)]
    checkpoint_stack: Vec<(usize, usize)>,
    /// Recorded storage actions.
    actions: StorageActions,
}

impl<'a> EvmPrecompileStorageProvider<'a> {
    /// Creates a new storage provider with the given gas limit, hardfork, and static flag.
    pub fn new(
        internals: EvmInternals<'a>,
        gas_limit: u64,
        reservoir: u64,
        spec: TempoHardfork,
        amsterdam_eip8037_enabled: bool,
        is_static: bool,
        gas_params: GasParams,
    ) -> Self {
        Self {
            internals,
            gas_tracker: GasTracker::new(gas_limit, gas_limit, reservoir),
            spec,
            amsterdam_eip8037_enabled,
            is_static,
            gas_params,
            tip1060_storage_credits_enabled: spec.is_t7(),
            tip1060_storage_credit_minting_enabled: true,
            non_creditable_slots: Rc::new(RefCell::new(NonCreditableSlots::empty())),
            #[cfg(debug_assertions)]
            checkpoint_stack: Vec::new(),
            actions: StorageActions::disabled(),
        }
    }

    /// Creates a new storage provider with maximum gas limit and non-static context.
    pub fn new_max_gas(internals: EvmInternals<'a>, cfg: &CfgEnv<TempoHardfork>) -> Self {
        Self::new(
            internals,
            u64::MAX,
            0,
            cfg.spec,
            cfg.enable_amsterdam_eip8037,
            false,
            cfg.gas_params.clone(),
        )
    }

    /// Creates a new storage provider with the given gas limit, deriving spec from `cfg`.
    pub fn new_with_gas_limit(
        internals: EvmInternals<'a>,
        cfg: &CfgEnv<TempoHardfork>,
        gas_limit: u64,
        reservoir: u64,
    ) -> Self {
        Self::new(
            internals,
            gas_limit,
            reservoir,
            cfg.spec,
            cfg.enable_amsterdam_eip8037,
            false,
            cfg.gas_params.clone(),
        )
    }

    /// Sets the storage actions for this provider.
    pub fn with_actions(mut self, actions: StorageActions) -> Self {
        self.actions = actions;
        self
    }

    /// Sets the transaction-local non-creditable clear-slot context for this provider.
    pub fn with_non_creditable_slots(mut self, slots: Rc<RefCell<NonCreditableSlots>>) -> Self {
        self.non_creditable_slots = slots;
        self
    }

    /// Replaces the recorded storage actions with an empty buffer, returning the previous actions.
    pub fn take_actions(&self) -> Option<Vec<StorageAction>> {
        self.actions.take()
    }

    /// Replaces the recorded storage actions with the given ones, returning the previous actions.
    pub fn replace_actions(&self, actions: Vec<StorageAction>) -> Option<Vec<StorageAction>> {
        self.actions.replace(actions)
    }

    #[inline]
    fn ensure_not_static(&self) -> Result<(), TempoPrecompileError> {
        match self.is_static {
            false => Ok(()),
            true => Err(TempoPrecompileError::StaticCallNotAllowed),
        }
    }

    #[inline]
    fn deduct_state_gas(&mut self, gas: u64) -> Result<(), TempoPrecompileError> {
        if !self.gas_tracker.record_state_cost(gas) {
            return Err(TempoPrecompileError::OutOfGas);
        }
        Ok(())
    }

    /// Performs a raw journaled SLOAD without metering gas or recording a storage action.
    #[inline]
    fn sload_journal(
        &mut self,
        address: Address,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, TempoPrecompileError> {
        let mut account = self.internals.load_account_mut(address)?;
        let val = account.sload(key, skip_cold_load)?;
        Ok(StateLoad::new(val.present_value, val.is_cold))
    }

    /// Performs a raw journaled SSTORE without metering gas or recording a storage action.
    #[inline]
    fn sstore_journal(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, TempoPrecompileError> {
        self.ensure_not_static()?;
        Ok(self
            .internals
            .load_account_mut(address)?
            .sstore(key, value, skip_cold_load)?)
    }

    /// Performs a metered precompile SLOAD, optionally recording the storage action.
    #[inline]
    fn sload_inner(
        &mut self,
        address: Address,
        key: U256,
        record: bool,
    ) -> Result<U256, TempoPrecompileError> {
        let additional_cost = self.gas_params.cold_storage_additional_cost();

        // T4+: pre-charge static gas to avoid cheap useless work.
        let skip_cold_load = if self.spec.is_t4() {
            self.deduct_gas(self.gas_params.warm_storage_read_cost())?;
            self.gas_tracker.remaining() < additional_cost
        } else {
            false
        };

        let result = self.sload_journal(address, key, skip_cold_load)?;
        if record {
            self.actions
                .record(StorageAction::Sload(address, key, result.data));
        }

        if !self.spec.is_t4() {
            self.deduct_gas(self.gas_params.warm_storage_read_cost())?;
        }

        // dynamic gas
        if result.is_cold {
            self.deduct_gas(additional_cost)?;
        }

        Ok(result.data)
    }

    /// Performs a metered precompile SSTORE and records `action` before storage-credit bookkeeping.
    #[inline]
    fn sstore_inner(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        action: impl FnOnce(&SStoreResult) -> StorageAction,
    ) -> Result<(), TempoPrecompileError> {
        // T12+: EIP-2200 sentry. SSTORE fails if the frame only has the call stipend remaining.
        if self.spec.is_t12() && self.gas_tracker.remaining() <= self.gas_params.call_stipend() {
            return Err(TempoPrecompileError::OutOfGas);
        }

        // T4+: pre-charge static gas before loading storage to avoid cheap useless work.
        let skip_cold_load = if self.spec.is_t4() {
            self.deduct_gas(self.gas_params.sstore_static_gas())?;
            self.gas_tracker.remaining() < self.gas_params.cold_storage_additional_cost()
        } else {
            false
        };

        let result = self.sstore_journal(address, key, value, skip_cold_load)?;
        self.actions.record(action(&result.data));

        if !self.spec.is_t4() {
            self.deduct_gas(self.gas_params.sstore_static_gas())?;
        }

        // TIP-1060 (T7+): run the storage credits policy so precompile-driven storage
        // writes honor the same accounting as the opcode-level SSTORE hook.
        if self.tip1060_storage_credits_enabled {
            sstore_storage_credits(self, address, Some(key), &result)?
        }

        // dynamic gas
        self.deduct_gas(
            self.gas_params
                .sstore_dynamic_gas(true, &result.data, result.is_cold),
        )?;

        // Track state gas (cold SSTORE zero->non-zero only)
        self.deduct_state_gas(self.gas_params.sstore_state_gas(&result.data))?;

        // refund gas.
        self.refund_gas(self.gas_params.sstore_refund(true, &result.data));

        Ok(())
    }

    #[inline]
    fn with_loaded_account<R>(
        &mut self,
        address: Address,
        f: impl FnOnce(bool, &AccountInfo) -> R,
    ) -> Result<R, TempoPrecompileError> {
        let additional_cost = self.gas_params.cold_account_additional_cost();

        // T4+: pre-charge static gas to avoid cheap useless work.
        let insufficient_gas_for_cold_load = if self.spec.is_t4() {
            self.deduct_gas(self.gas_params.warm_storage_read_cost())?;
            self.gas_tracker.remaining() < additional_cost
        } else {
            false
        };

        let mut account = self
            .internals
            .load_account_mut_skip_cold_load(address, insufficient_gas_for_cold_load)?;

        if !self.spec.is_t4() {
            deduct_gas(
                &mut self.gas_tracker,
                self.gas_params.warm_storage_read_cost(),
            )?;
        }

        // Dynamic gas.
        if account.is_cold {
            deduct_gas(&mut self.gas_tracker, additional_cost)?;
        }

        let exists = !account.data.account().is_loaded_as_not_existing();
        account.load_code()?;

        Ok(f(exists, &account.data.account().info))
    }
}

impl crate::storage_credits::StorageCreditsBackend for EvmPrecompileStorageProvider<'_> {
    type Error = TempoPrecompileError;

    #[inline]
    fn gas_tracker(&mut self) -> &mut GasTracker {
        &mut self.gas_tracker
    }

    #[inline]
    fn gas_params(&self) -> &GasParams {
        &self.gas_params
    }

    #[inline]
    fn sload(
        &mut self,
        address: Address,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, Self::Error> {
        let val = self.sload_journal(address, key, skip_cold_load)?;
        self.actions
            .record_always(StorageAction::Sload(address, key, val.data));
        Ok(val)
    }

    #[inline]
    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        skip_cold_load: bool,
    ) -> Result<SstoreTransitionFlags, Self::Error> {
        let val = self.sstore_journal(address, key, value, skip_cold_load)?;
        self.actions.record_always(StorageAction::Sstore(
            address,
            key,
            val.data.present_value,
            value,
        ));
        Ok(val.into())
    }

    #[inline]
    fn tload(&mut self, address: Address, key: U256) -> U256 {
        self.internals.tload(address, key)
    }

    #[inline]
    fn tstore(&mut self, address: Address, key: U256, value: U256) -> Result<(), Self::Error> {
        self.ensure_not_static()?;
        self.internals.tstore(address, key, value);
        Ok(())
    }

    #[inline]
    fn is_non_creditable_slot(&mut self, owner: Address, key: U256) -> bool {
        self.non_creditable_slots
            .borrow()
            .is_non_creditable_slot(owner, key)
    }

    #[inline]
    fn tip1060_storage_credit_minting_enabled(&self) -> bool {
        self.tip1060_storage_credit_minting_enabled
    }
}

impl<'a> PrecompileStorageProvider for EvmPrecompileStorageProvider<'a> {
    fn chain_id(&self) -> u64 {
        self.internals.chain_id()
    }

    fn block_env(&self) -> &TempoBlockEnv {
        self.internals
            .block_env_downcast_ref::<TempoBlockEnv>()
            .expect("EvmPrecompileStorageProvider requires TempoBlockEnv")
    }

    #[inline]
    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<(), TempoPrecompileError> {
        self.ensure_not_static()?;

        let code_len = code.len();
        self.deduct_gas(self.gas_params.code_deposit_cost(code_len))?;

        // Track state gas for code deposit
        self.deduct_state_gas(self.gas_params.code_deposit_state_gas(code_len))?;

        let was_empty = {
            let mut account = self.internals.load_account_mut(address)?;
            let was_empty = account.data.account().info.is_empty();
            account.set_code_and_hash_slow(code);
            was_empty
        };

        // TIP-1016: charge TIP20 deployments as CREATE.
        if self.amsterdam_eip8037_enabled && was_empty {
            self.deduct_gas(self.gas_params.create_cost())?;
            self.deduct_state_gas(self.gas_params.create_state_gas())?;
            self.deduct_gas(self.gas_params.keccak256_cost(code_len.div_ceil(32)))?;
        }

        Ok(())
    }

    #[inline]
    fn with_account_info(
        &mut self,
        address: Address,
        f: &mut dyn FnMut(&AccountInfo),
    ) -> Result<(), TempoPrecompileError> {
        self.with_loaded_account(address, |_, info| f(info))
    }

    #[inline]
    fn account_code(&mut self, address: Address) -> Result<(B256, Bytecode), TempoPrecompileError> {
        self.with_loaded_account(address, |exists, info| {
            let code_hash = if exists { info.code_hash } else { B256::ZERO };
            let code = info.code.clone().unwrap_or_default();
            (code_hash, code)
        })
    }

    #[inline]
    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.ensure_not_static()?;

        self.sstore_inner(address, key, value, |result| {
            StorageAction::Sstore(address, key, result.present_value, value)
        })
    }

    #[inline]
    fn sinc(
        &mut self,
        address: Address,
        key: U256,
        delta: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.ensure_not_static()?;

        let current = self.sload_inner(address, key, false)?;
        let value = current
            .checked_add(delta)
            .ok_or_else(TempoPrecompileError::under_overflow)?;

        // If the value goes from zero to non-zero, do not record it as `Sinc`,
        // because it requires special TIP-1060 gas credits accounting.
        let sstore_action = if current == U256::ZERO && value != U256::ZERO {
            self.actions
                .record(StorageAction::Sload(address, key, current));
            StorageAction::Sstore(address, key, current, value)
        } else {
            StorageAction::Sinc(address, key, current, delta)
        };

        self.sstore_inner(address, key, value, |_| sstore_action)
    }

    #[inline]
    fn sdec(
        &mut self,
        address: Address,
        key: U256,
        delta: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.ensure_not_static()?;

        let current = self.sload_inner(address, key, false)?;
        let value = current
            .checked_sub(delta)
            .ok_or_else(|| TempoPrecompileError::storage_delta_underflow(current))?;

        // If the value goes from non-zero to zero, do not record it as `Sdec`,
        // because it requires special TIP-1060 gas credits accounting.
        let sstore_action = if current != U256::ZERO && value == U256::ZERO {
            self.actions
                .record(StorageAction::Sload(address, key, current));
            StorageAction::Sstore(address, key, current, value)
        } else {
            StorageAction::Sdec(address, key, current, delta)
        };

        self.sstore_inner(address, key, value, |_| sstore_action)
    }

    #[inline]
    fn tstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.ensure_not_static()?;

        self.deduct_gas(self.gas_params.warm_storage_read_cost())?;
        self.internals.tstore(address, key, value);
        Ok(())
    }

    #[inline]
    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), TempoPrecompileError> {
        self.ensure_not_static()?;

        self.deduct_gas(
            gas::LOG
                + self
                    .gas_params
                    .log_cost(event.topics().len() as u8, event.data.len() as u64),
        )?;

        self.internals.log(Log {
            address,
            data: event,
        });

        Ok(())
    }

    #[inline]
    fn sload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError> {
        self.sload_inner(address, key, true)
    }

    #[inline]
    fn tload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError> {
        self.deduct_gas(self.gas_params.warm_storage_read_cost())?;

        Ok(self.internals.tload(address, key))
    }

    #[inline]
    fn deduct_gas(&mut self, gas: u64) -> Result<(), TempoPrecompileError> {
        deduct_gas(&mut self.gas_tracker, gas)
    }

    #[inline]
    fn refund_gas(&mut self, gas: i64) {
        self.gas_tracker.record_refund(gas);
    }

    #[inline]
    fn gas_limit(&self) -> u64 {
        self.gas_tracker.limit()
    }

    #[inline]
    fn gas_used(&self) -> u64 {
        self.gas_tracker.limit() - self.gas_tracker.remaining()
    }

    #[inline]
    fn state_gas_used(&self) -> u64 {
        // SAFETY: we never decrement the state gas spent counter
        self.gas_tracker.state_gas_spent() as u64
    }

    #[inline]
    fn state_gas_spilled(&self) -> u64 {
        self.gas_tracker.state_gas_spilled()
    }

    #[inline]
    fn gas_refunded(&self) -> i64 {
        self.gas_tracker.refunded()
    }

    #[inline]
    fn reservoir(&self) -> u64 {
        self.gas_tracker.reservoir()
    }

    #[inline]
    fn spec(&self) -> TempoHardfork {
        self.spec
    }

    #[inline]
    fn storage_actions(&self) -> StorageActions {
        self.actions.clone()
    }

    #[inline]
    fn amsterdam_eip8037_enabled(&self) -> bool {
        self.amsterdam_eip8037_enabled
    }

    #[inline]
    fn is_static(&self) -> bool {
        self.is_static
    }

    #[inline]
    fn checkpoint(&mut self) -> JournalCheckpoint {
        let cp = self.internals.checkpoint();
        #[cfg(debug_assertions)]
        self.track_checkpoint(&cp);
        cp
    }

    #[inline]
    fn checkpoint_commit(&mut self, _checkpoint: JournalCheckpoint) {
        #[cfg(debug_assertions)]
        self.assert_lifo(&_checkpoint, "commit");
        self.internals.checkpoint_commit()
    }

    #[inline]
    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        #[cfg(debug_assertions)]
        self.assert_lifo(&checkpoint, "revert");
        self.internals.checkpoint_revert(checkpoint)
    }

    #[inline]
    fn set_tip1060_storage_credits(&mut self, enabled: bool) {
        self.tip1060_storage_credits_enabled = enabled && self.spec.is_t7();
    }

    #[inline]
    fn set_tip1060_storage_credit_minting(&mut self, enabled: bool) {
        self.tip1060_storage_credit_minting_enabled = enabled;
    }
}

/// LIFO checkpoint validation (debug builds only).
///
/// Since `EvmInternals` doesn't expose revm's journal depth, we mirror it by
/// recording each checkpoint's (`journal_i`, `log_i`) on creation and asserting
/// that commits/reverts always resolve the most recent checkpoint first.
#[cfg(debug_assertions)]
impl EvmPrecompileStorageProvider<'_> {
    /// Records a newly created checkpoint for later LIFO validation.
    fn track_checkpoint(&mut self, cp: &JournalCheckpoint) {
        self.checkpoint_stack.push((cp.journal_i, cp.log_i));
    }

    /// Panics if `cp` is not the most recently created checkpoint.
    fn assert_lifo(&mut self, cp: &JournalCheckpoint, op: &str) {
        let top = self
            .checkpoint_stack
            .pop()
            .unwrap_or_else(|| panic!("checkpoint_{op}: no active checkpoint"));

        assert_eq!(
            (cp.journal_i, cp.log_i),
            top,
            "out-of-order checkpoint {op} (expected top of stack)"
        );
    }
}

bitflags! {
    /// SSTORE transition flags that drive gas/refund accounting.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SstoreTransitionFlags: u8 {
        /// The slot's transaction-start value is zero.
        const ORIGINAL_ZERO = 1 << 0;
        /// The slot's pre-SSTORE value is zero.
        const PRESENT_ZERO = 1 << 1;
        /// The slot's post-SSTORE value is zero.
        const NEW_ZERO = 1 << 2;
        /// The slot's transaction-start value equals its pre-SSTORE value.
        const ORIGINAL_EQ_PRESENT = 1 << 3;
        /// The slot's transaction-start value equals its post-SSTORE value.
        const ORIGINAL_EQ_NEW = 1 << 4;
        /// The slot's pre-SSTORE current value equals its post-SSTORE value.
        const PRESENT_EQ_NEW = 1 << 5;
    }
}

impl SstoreTransitionFlags {
    /// Computes the SSTORE transition flags from the values that drive gas/refund accounting.
    pub fn from_values(original: U256, present: U256, new: U256) -> Self {
        let mut flags = Self::empty();

        if original.is_zero() {
            flags |= Self::ORIGINAL_ZERO;
        }
        if present.is_zero() {
            flags |= Self::PRESENT_ZERO;
        }
        if new.is_zero() {
            flags |= Self::NEW_ZERO;
        }
        if original == present {
            flags |= Self::ORIGINAL_EQ_PRESENT;
        }
        if original == new {
            flags |= Self::ORIGINAL_EQ_NEW;
        }
        if present == new {
            flags |= Self::PRESENT_EQ_NEW;
        }

        flags
    }

    /// Returns whether the write changes slot occupancy.
    pub fn crosses_zero_boundary(&self) -> bool {
        self.contains(Self::PRESENT_ZERO) != self.contains(Self::NEW_ZERO)
    }

    /// Returns whether the write creates an occupied slot.
    pub fn is_zero_to_nonzero(&self) -> bool {
        self.contains(Self::PRESENT_ZERO) && !self.contains(Self::NEW_ZERO)
    }

    /// Returns whether the write clears an occupied slot.
    pub fn is_nonzero_to_zero(&self) -> bool {
        !self.contains(Self::PRESENT_ZERO) && self.contains(Self::NEW_ZERO)
    }

    /// Returns whether the write changes the present value.
    pub fn changes_present(&self) -> bool {
        !self.contains(Self::PRESENT_EQ_NEW)
    }

    /// Returns whether this slot is still clean before the write.
    ///
    /// In EVM SSTORE terminology, "clean" means the transaction has not changed
    /// the slot yet, so the transaction-start value (`original`) still equals
    /// the current pre-write value (`present`).
    pub fn is_original_eq_present(&self) -> bool {
        self.contains(Self::ORIGINAL_EQ_PRESENT)
    }

    /// Returns whether the warm clean-update SSTORE cost applies.
    ///
    /// This is the `present != new && original == present` case: the write
    /// changes a slot for the first time in the transaction. Dirty writes
    /// (`original != present`) use different SSTORE accounting and do not pay
    /// this clean-update charge again.
    pub fn charges_clean_update(&self) -> bool {
        self.changes_present() && self.is_original_eq_present()
    }
}

impl From<&StateLoad<SStoreResult>> for SstoreTransitionFlags {
    fn from(result: &StateLoad<SStoreResult>) -> Self {
        Self::from_values(
            result.data.original_value,
            result.data.present_value,
            result.data.new_value,
        )
    }
}

impl From<StateLoad<SStoreResult>> for SstoreTransitionFlags {
    fn from(result: StateLoad<SStoreResult>) -> Self {
        Self::from(&result)
    }
}

/// Deducts gas from the remaining gas and returns an error if insufficient.
#[inline]
pub fn deduct_gas(
    gas_tracker: &mut GasTracker,
    additional_cost: u64,
) -> Result<(), TempoPrecompileError> {
    if !gas_tracker.record_regular_cost(additional_cost) {
        return Err(TempoPrecompileError::OutOfGas);
    }
    Ok(())
}


