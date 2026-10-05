//! ABI dispatch for the storage credits precompile.

use crate::{
    Precompile, charge_input_cost, dispatch, mutate, storage_credits::StorageCredits, view,
};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IStorageCredits;

impl Precompile for StorageCredits {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IStorageCredits::IStorageCreditsCalls {
                    balanceOf(call) => view(call, |c| self.balance_of(c.account)),
                    modeOf(call) => view(call, |c| self.mode_of(c.account).map(Into::into)),
                    budgetOf(call) => view(call, |c| self.budget_of(c.account)),
                    setMode(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_mode(sender, c.newMode)
                    }),
                    setBudget(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_budget(sender, c.credits)
                    })
                }
            }
        )
    }
}


