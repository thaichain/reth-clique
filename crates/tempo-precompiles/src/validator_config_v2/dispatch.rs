//! ABI dispatch for the [`ValidatorConfigV2`] precompile (T2+).

use super::*;
use crate::{Precompile, charge_input_cost, dispatch, mutate, view};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IValidatorConfigV2;

impl Precompile for ValidatorConfigV2 {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        // Pre-T2: behave like an empty contract (call succeeds, no execution)
        if !self.storage.spec().is_t2() {
            return Ok(self.storage.success_output(Default::default()));
        }

        dispatch!(
            calldata,
            |call| match call {
                IValidatorConfigV2::IValidatorConfigV2Calls {
                    owner(call) => view(call, |_| self.owner()),
                    getActiveValidators(call) => view(call, |_| self.get_active_validators()),
                    getInitializedAtHeight(call) => view(call, |_| self.get_initialized_at_height()),
                    validatorCount(call) => view(call, |_| self.validator_count()),
                    validatorByIndex(call) => view(call, |c| self.validator_by_index(c.index)),
                    validatorByAddress(call) => view(call, |c| self.validator_by_address(c.validatorAddress)),
                    validatorByPublicKey(call) => view(call, |c| self.validator_by_public_key(c.publicKey)),
                    getNextNetworkIdentityRotationEpoch(call) => view(call, |_| self.get_next_network_identity_rotation_epoch()),
                    isInitialized(call) => view(call, |_| self.is_initialized()),

                    addValidator(call) => mutate(call, msg_sender, |sender, c| self.add_validator(sender, c)),
                    deactivateValidator(call) => mutate(call, msg_sender, |sender, c| self.deactivate_validator(sender, c)),
                    rotateValidator(call) => mutate(call, msg_sender, |sender, c| self.rotate_validator(sender, c)),
                    setFeeRecipient(call) => mutate(call, msg_sender, |sender, c| self.set_fee_recipient(sender, c)),
                    setIpAddresses(call) => mutate(call, msg_sender, |sender, c| self.set_ip_addresses(sender, c)),
                    transferValidatorOwnership(call) => mutate(call, msg_sender, |sender, c| {
                        self.transfer_validator_ownership(sender, c)
                    }),
                    transferOwnership(call) => mutate(call, msg_sender, |sender, c| self.transfer_ownership(sender, c)),
                    setNetworkIdentityRotationEpoch(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_network_identity_rotation_epoch(sender, c)
                    }),
                    migrateValidator(call) => mutate(call, msg_sender, |sender, c| self.migrate_validator(sender, c)),
                    initializeIfMigrated(call) => mutate(call, msg_sender, |sender, _| self.initialize_if_migrated(sender))
                }
            }
        )
    }
}


