//! ABI dispatch for the [`AccountKeychain`] precompile.

use super::{AccountKeychain, KeyRestrictions, TokenLimit, authorizeKeyCall};
use crate::{Precompile, charge_input_cost, dispatch, mutate, view};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::{AccountKeychainError, IAccountKeychain};

impl Precompile for AccountKeychain {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IAccountKeychain::IAccountKeychainCalls {
                    authorizeKey_0(call) => {
                        if self.storage.spec().is_t3() {
                            return self.storage.error_result(
                                AccountKeychainError::legacy_authorize_key_selector_changed(
                                    authorizeKeyCall::SELECTOR.into(),
                                ),
                            );
                        }

                        let call = authorizeKeyCall {
                            keyId: call.keyId,
                            signatureType: call.signatureType,
                            config: KeyRestrictions {
                                expiry: call.expiry,
                                enforceLimits: call.enforceLimits,
                                limits: call
                                    .limits
                                    .into_iter()
                                    .map(|limit| TokenLimit {
                                        token: limit.token,
                                        amount: limit.amount,
                                        period: 0,
                                    })
                                    .collect(),
                                allowAnyCalls: true,
                                allowedCalls: vec![],
                            },
                        };

                        mutate(call, msg_sender, |sender, c| {
                            self.authorize_key(sender, c.keyId, c.signatureType, c.config, None)
                        })
                    },
                    #[schedule(since = T3)]
                    authorizeKey_1(call) => mutate(call, msg_sender, |sender, c| {
                        self.authorize_key(sender, c.keyId, c.signatureType, c.config, None)
                    }),
                    #[schedule(since = T5)]
                    authorizeKey_2(call) => mutate(call, msg_sender, |sender, c| {
                        self.authorize_key(sender, c.keyId, c.signatureType, c.config, Some(c.witness))
                    }),
                    #[schedule(since = T6)]
                    authorizeAdminKey(call) => mutate(call, msg_sender, |sender, c| {
                        self.authorize_admin_key(sender, c.keyId, c.signatureType, Some(c.witness))
                    }),
                    #[schedule(since = T5)]
                    burnKeyAuthorizationWitness(call) => mutate(call, msg_sender, |sender, c| {
                        self.burn_key_authorization_witness(sender, c)
                    }),
                    revokeKey(call) => mutate(call, msg_sender, |sender, c| self.revoke_key(sender, c)),
                    updateSpendingLimit(call) => mutate(call, msg_sender, |sender, c| {
                        self.update_spending_limit(sender, c)
                    }),
                    #[schedule(since = T3)]
                    setAllowedCalls(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_allowed_calls(sender, c)
                    }),
                    #[schedule(since = T3)]
                    removeAllowedCalls(call) => mutate(call, msg_sender, |sender, c| {
                        self.remove_allowed_calls(sender, c)
                    }),
                    getKey(call) => view(call, |c| self.get_key(c)),
                    #[schedule(until = T3)]
                    getRemainingLimit(call) => view(call, |c| self.get_remaining_limit(c)),
                    #[schedule(since = T3)]
                    getRemainingLimitWithPeriod(call) => view(call, |c| self.get_remaining_limit_with_period(c)),
                    #[schedule(since = T3)]
                    getAllowedCalls(call) => view(call, |c| self.get_allowed_calls(c)),
                    #[schedule(since = T5)]
                    isKeyAuthorizationWitnessBurned(call) => view(call, |c| self.is_key_authorization_witness_burned(c)),
                    #[schedule(since = T6)]
                    isAdminKey(call) => view(call, |c| self.is_admin_key(c.account, c.keyId)),
                    getTransactionKey(call) => view(call, |c| self.get_transaction_key(c, msg_sender))
                }
            }
        )
    }
}


