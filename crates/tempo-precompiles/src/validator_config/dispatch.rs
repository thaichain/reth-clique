//! ABI dispatch for the [`ValidatorConfig`] (V1) precompile.

use super::ValidatorConfig;
use crate::{Precompile, charge_input_cost, dispatch, error::TempoPrecompileError, mutate, view};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IValidatorConfig;

impl Precompile for ValidatorConfig {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }
        dispatch!(
            calldata,
            |call| match call {
                IValidatorConfig::IValidatorConfigCalls {
                    // View functions
                    owner(call) => view(call, |_| self.owner()),
                    getValidators(call) => view(call, |_| self.get_validators()),
                    getNextFullDkgCeremony(call) => view(call, |_| self.get_next_full_dkg_ceremony()),
                    validatorsArray(call) => view(call, |c| {
                        let index = u64::try_from(c.index)
                            .map_err(|_| TempoPrecompileError::array_oob())?;
                        self.validators_array(index)
                    }),
                    validators(call) => view(call, |c| self.validators(c.validator)),
                    validatorCount(call) => view(call, |_| self.validator_count()),

                    // Mutate functions
                    addValidator(call) => mutate(call, msg_sender, |sender, c| self.add_validator(sender, c)),
                    updateValidator(call) => mutate(call, msg_sender, |sender, c| self.update_validator(sender, c)),
                    changeValidatorStatus(call) => mutate(call, msg_sender, |sender, c| self.change_validator_status(sender, c)),
                    #[schedule(since = T1)]
                    changeValidatorStatusByIndex(call) => mutate(call, msg_sender, |sender, c| {
                        self.change_validator_status_by_index(sender, c)
                    }),
                    changeOwner(call) => mutate(call, msg_sender, |sender, c| self.change_owner(sender, c)),
                    setNextFullDkgCeremony(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_next_full_dkg_ceremony(sender, c)
                    })
                }
            }
        )
    }
}


