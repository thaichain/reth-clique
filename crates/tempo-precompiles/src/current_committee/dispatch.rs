//! ABI dispatch for the [`CurrentCommittee`] precompile.

use crate::{
    Precompile, charge_input_cost, current_committee::CurrentCommittee, dispatch, mutate, view,
};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::ICurrentCommittee;
#[cfg(test)]
use tempo_contracts::precompiles::ICurrentCommittee::ICurrentCommitteeCalls;

impl Precompile for CurrentCommittee {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                ICurrentCommittee::ICurrentCommitteeCalls {
                    getCommitteeMembers(call) => view(call, |_| self.get_committee_members()),
                    setCommitteeMembers(call) => {
                        mutate(call, msg_sender, |sender, c| self.set_committee_members(sender, c))
                    }
                }
            }
        )
    }
}


