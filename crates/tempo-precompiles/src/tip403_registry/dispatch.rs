//! ABI dispatch for the [`TIP403Registry`] precompile.

use crate::{
    Precompile, charge_input_cost, dispatch, mutate,
    tip403_registry::{AuthRole, TIP403Registry},
    view,
};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::ITIP403Registry;

impl Precompile for TIP403Registry {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                ITIP403Registry::ITIP403RegistryCalls {
                    policyIdCounter(call) => view(call, |_| self.policy_id_counter()),
                    policyExists(call) => view(call, |c| self.policy_exists(c)),
                    #[schedule(since = T9)]
                    tokenTransferPolicyId(call) => view(call, |c| self.token_transfer_policy_id(c)),
                    policyData(call) => view(call, |c| self.policy_data(c)),
                    isAuthorized(call) => view(call, |c| {
                        self.is_authorized_as(c.policyId, c.user, AuthRole::Transfer)
                    }),
                    #[schedule(since = T2)]
                    isAuthorizedSender(call) => view(call, |c| {
                        self.is_authorized_as(c.policyId, c.user, AuthRole::Sender)
                    }),
                    #[schedule(since = T2)]
                    isAuthorizedRecipient(call) => view(call, |c| {
                        self.is_authorized_as(c.policyId, c.user, AuthRole::Recipient)
                    }),
                    #[schedule(since = T2)]
                    isAuthorizedMintRecipient(call) => view(call, |c| {
                        self.is_authorized_as(c.policyId, c.user, AuthRole::MintRecipient)
                    }),
                    #[schedule(since = T2)]
                    compoundPolicyData(call) => view(call, |c| self.compound_policy_data(c)),
                    #[schedule(since = T6)]
                    receivePolicy(call) => view(call, |c| self.receive_policy(c.account)),
                    #[schedule(since = T6)]
                    validateReceivePolicy(call) => view(call, |c| {
                        let blocked_reason = self
                            .validate_receive_policy(c.token, c.sender, c.receiver)?
                            .unwrap_or(ITIP403Registry::BlockedReason::NONE);
                        Ok(ITIP403Registry::validateReceivePolicyReturn {
                            authorized: blocked_reason == ITIP403Registry::BlockedReason::NONE,
                            blockedReason: blocked_reason,
                        })
                    }),
                    #[schedule(since = T6)]
                    setReceivePolicy(call) => mutate(call, msg_sender, |sender, c| self.set_receive_policy(sender, c)),
                    #[schedule(since = T9)]
                    migrateTransferPolicyIds(call) => mutate(call, msg_sender, |_, c| {
                        self.migrate_transfer_policy_ids(c)
                    }),
                    createPolicy(call) => mutate(call, msg_sender, |sender, c| self.create_policy(sender, c)),
                    createPolicyWithAccounts(call) => mutate(call, msg_sender, |sender, c| {
                        self.create_policy_with_accounts(sender, c)
                    }),
                    setPolicyAdmin(call) => mutate(call, msg_sender, |sender, c| self.set_policy_admin(sender, c)),
                    modifyPolicyWhitelist(call) => mutate(call, msg_sender, |sender, c| self.modify_policy_whitelist(sender, c)),
                    modifyPolicyBlacklist(call) => mutate(call, msg_sender, |sender, c| self.modify_policy_blacklist(sender, c)),
                    #[schedule(since = T2)]
                    createCompoundPolicy(call) => mutate(call, msg_sender, |sender, c| self.create_compound_policy(sender, c))
                }
            }
        )
    }
}


