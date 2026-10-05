use super::SignatureVerifier;
use crate::{Precompile, charge_input_cost, dispatch, view};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::{ISignatureVerifier, SignatureVerifierError};
use tempo_primitives::MAX_WEBAUTHN_SIGNATURE_LENGTH;

/// Maximum valid calldata size: `verify(address,bytes32,bytes)` with a WebAuthn signature is the
/// worst case. ABI encoding pads the dynamic `bytes` field independently, so only round the
/// dynamic portion: selector(4) + args(4×32) + padded_sig_bytes.
const MAX_CALLDATA_LEN: usize =
    4 + 32 * 4 + (MAX_WEBAUTHN_SIGNATURE_LENGTH + 1).next_multiple_of(32);

impl Precompile for SignatureVerifier {
    fn call(&mut self, calldata: &[u8], _msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        if calldata.len() > MAX_CALLDATA_LEN {
            return Ok(self
                .storage
                .abi_revert(SignatureVerifierError::invalid_format()));
        }

        dispatch!(
            calldata,
            |call| match call {
                ISignatureVerifier::ISignatureVerifierCalls {
                    recover(call) => view(call, |c| self.recover(c.hash, c.signature)),
                    verify(call) => view(call, |c| {
                        self.recover(c.hash, c.signature).map(|sig| sig == c.signer)
                    }),
                    #[schedule(since = T6)]
                    verifyKeychain(call) => view(call, |c| {
                        self.verify_keychain(c.account, c.hash, c.signature)
                    }),
                    #[schedule(since = T6)]
                    verifyKeychainAdmin(call) => view(call, |c| {
                        self.verify_keychain_admin(c.account, c.hash, c.signature)
                    }),
                }
            }
        )
    }
}


