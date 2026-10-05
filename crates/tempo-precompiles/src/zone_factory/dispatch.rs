//! ABI dispatch for the [`ZoneFactory`] precompile.

use crate::{Precompile, charge_input_cost, dispatch, mutate, view};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IZoneFactory;

use super::ZoneFactory;

impl Precompile for ZoneFactory {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IZoneFactory::IZoneFactoryCalls {
                    owner(call) => view(call, |_| self.owner()),
                    transferOwnership(call) => {
                        mutate(call, msg_sender, |sender, call| {
                            self.transfer_ownership(sender, call)
                        })
                    },
                    createZone(call) => {
                        mutate(call, msg_sender, |sender, call| self.create_zone(sender, call))
                    },
                    nextZoneId(call) => view(call, |_| self.next_zone_id()),
                    zones(call) => view(call, |call| self.zone(call.id)),
                    isZonePortal(call) => view(call, |call| self.is_zone_portal(call.portal)),
                }
            }
        )
    }
}


