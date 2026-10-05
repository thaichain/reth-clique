//! ABI dispatch for the [`NonceManager`] precompile.

use crate::{Precompile, charge_input_cost, dispatch, nonce::NonceManager, view};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::INonce;
impl Precompile for NonceManager {
    fn call(&mut self, calldata: &[u8], _msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(calldata, |call| match call {
            INonce::INonceCalls { getNonce(call) => view(call, |c| self.get_nonce(c)) }
        })
    }
}


