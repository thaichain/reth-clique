use crate::{
    Precompile, address_registry::AddressRegistry, charge_input_cost, dispatch, mutate, view,
};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IAddressRegistry;
use tempo_primitives::{MasterId, TempoAddressExt, UserTag};

impl Precompile for AddressRegistry {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IAddressRegistry::IAddressRegistryCalls {
                    // Registration
                    registerVirtualMaster(call) => mutate(call, msg_sender, |sender, c| {
                        self.register_virtual_master(sender, c)
                    }),
                    // View functions
                    getMaster(call) => view(call, |c| {
                        Ok(self.get_master(c.masterId)?.unwrap_or(Address::ZERO))
                    }),
                    resolveRecipient(call) => view(call, |c| self.resolve_recipient(c.to)),
                    resolveVirtualAddress(call) => view(call, |c| {
                        self.resolve_virtual_address(c.virtualAddr)
                    }),
                    // Pure functions
                    isVirtualAddress(call) => view(call, |c| Ok(c.addr.is_virtual())),
                    decodeVirtualAddress(call) => view(call, |c| {
                        let (is_virtual, master_id, user_tag) = match c.addr.decode_virtual() {
                            Some((mid, tag)) => (true, mid, tag),
                            None => (false, MasterId::ZERO, UserTag::ZERO),
                        };
                        Ok((is_virtual, master_id, user_tag).into())
                    }),
                    #[schedule(since = T5)]
                    isImplicitlyApproved(call) => view(call, |c| {
                        Ok(self.is_implicitly_approved(c.addr))
                    })
                }
            }
        )
    }
}


