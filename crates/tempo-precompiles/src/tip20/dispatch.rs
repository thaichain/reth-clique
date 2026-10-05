//! ABI dispatch for the [`TIP20Token`] precompile.

use crate::{
    Precompile, charge_input_cost, dispatch, mutate,
    storage::ContractStorage,
    tip20::{ITIP20, TIP20Token},
    view,
};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::{IRolesAuth, TIP20Error};

impl Precompile for TIP20Token {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        // Ensure that the token is initialized (has bytecode)
        let initialized = match self.is_initialized() {
            Ok(v) => v,
            Err(_) if !self.storage.spec().is_t4() => false,
            Err(e) => return self.storage.error_result(e),
        };
        if !initialized {
            return self.storage.error_result(TIP20Error::uninitialized());
        }

        dispatch!(
            calldata,
            |call| match call {
                ITIP20::ITIP20Calls {
                    // Metadata functions
                    name(call) => view(call, |_| self.name()),
                    symbol(call) => view(call, |_| self.symbol()),
                    decimals(call) => view(call, |_| self.decimals()),
                    currency(call) => view(call, |_| self.currency()),
                    totalSupply(call) => view(call, |_| self.total_supply()),
                    supplyCap(call) => view(call, |_| self.supply_cap()),
                    transferPolicyId(call) => view(call, |_| self.transfer_policy_id()),
                    paused(call) => view(call, |_| self.paused()),
                    #[schedule(since = T5)]
                    logoURI(call) => view(call, |_| self.logo_uri()),

                    // View functions
                    balanceOf(call) => view(call, |c| self.balance_of(c)),
                    allowance(call) => view(call, |c| self.allowance(c)),
                    quoteToken(call) => view(call, |_| self.quote_token()),
                    nextQuoteToken(call) => view(call, |_| self.next_quote_token()),
                    PAUSE_ROLE(call) => view(call, |_| Ok(Self::pause_role())),
                    UNPAUSE_ROLE(call) => view(call, |_| Ok(Self::unpause_role())),
                    ISSUER_ROLE(call) => view(call, |_| Ok(Self::issuer_role())),
                    BURN_BLOCKED_ROLE(call) => view(call, |_| Ok(Self::burn_blocked_role())),
                    #[schedule(since = T12)]
                    BURN_AT_ROLE(call) => view(call, |_| Ok(Self::burn_at_role())),

                    // State changing functions
                    transferFrom(call) => mutate(call, msg_sender, |sender, c| self.transfer_from(sender, c)),
                    transfer(call) => mutate(call, msg_sender, |sender, c| self.transfer(sender, c)),
                    approve(call) => mutate(call, msg_sender, |sender, c| self.approve(sender, c)),
                    changeTransferPolicyId(call) => mutate(call, msg_sender, |sender, c| {
                        self.change_transfer_policy_id(sender, c)
                    }),
                    setSupplyCap(call) => mutate(call, msg_sender, |sender, c| self.set_supply_cap(sender, c)),
                    #[schedule(since = T5)]
                    setLogoURI(call) => mutate(call, msg_sender, |sender, c| self.set_logo_uri(sender, c)),
                    pause(call) => mutate(call, msg_sender, |sender, c| self.pause(sender, c)),
                    unpause(call) => mutate(call, msg_sender, |sender, c| self.unpause(sender, c)),
                    setNextQuoteToken(call) => mutate(call, msg_sender, |sender, c| self.set_next_quote_token(sender, c)),
                    completeQuoteTokenUpdate(call) => mutate(call, msg_sender, |sender, c| {
                        self.complete_quote_token_update(sender, c)
                    }),
                    mint(call) => mutate(call, msg_sender, |sender, c| self.mint(sender, c)),
                    mintWithMemo(call) => mutate(call, msg_sender, |sender, c| self.mint_with_memo(sender, c)),
                    burn(call) => mutate(call, msg_sender, |sender, c| self.burn(sender, c)),
                    burnWithMemo(call) => mutate(call, msg_sender, |sender, c| self.burn_with_memo(sender, c)),
                    burnBlocked(call) => mutate(call, msg_sender, |sender, c| {
                        self.burn_blocked(sender, c.from, c.amount, true)
                    }),
                    #[schedule(since = T12)]
                    burnAt(call) => mutate(call, msg_sender, |sender, c| self.burn_at(sender, c)),
                    transferWithMemo(call) => mutate(call, msg_sender, |sender, c| self.transfer_with_memo(sender, c)),
                    transferFromWithMemo(call) => mutate(call, msg_sender, |sender, c| {
                        self.transfer_from_with_memo(sender, c)
                    }),
                    distributeReward(call) => mutate(call, msg_sender, |sender, c| self.distribute_reward(sender, c)),
                    setRewardRecipient(call) => mutate(call, msg_sender, |sender, c| self.set_reward_recipient(sender, c)),
                    claimRewards(call) => mutate(call, msg_sender, |sender, _| self.claim_rewards(sender)),
                    globalRewardPerToken(call) => view(call, |_| self.get_global_reward_per_token()),
                    optedInSupply(call) => view(call, |_| self.get_opted_in_supply()),
                    userRewardInfo(call) => view(call, |c| self.get_user_reward_info(c.account).map(|info| info.into())),
                    getPendingRewards(call) => view(call, |c| self.get_pending_rewards(c.account)),

                    #[schedule(since = T2)]
                    permit(call) => mutate(call, msg_sender, |_, c| self.permit(c)),
                    #[schedule(since = T2)]
                    nonces(call) => view(call, |c| self.nonces(c)),
                    #[schedule(since = T2)]
                    DOMAIN_SEPARATOR(call) => view(call, |_| self.domain_separator())
                }

                IRolesAuth::IRolesAuthCalls {
                    // RolesAuth functions
                    hasRole(call) => view(call, |c| self.has_role(c)),
                    getRoleAdmin(call) => view(call, |c| self.get_role_admin(c)),
                    grantRole(call) => mutate(call, msg_sender, |sender, c| self.grant_role(sender, c)),
                    revokeRole(call) => mutate(call, msg_sender, |sender, c| self.revoke_role(sender, c)),
                    renounceRole(call) => mutate(call, msg_sender, |sender, c| self.renounce_role(sender, c)),
                    setRoleAdmin(call) => mutate(call, msg_sender, |sender, c| self.set_role_admin(sender, c))
                }
            }
        )
    }
}


