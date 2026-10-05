//! ABI dispatch for the [`TipFeeManager`] precompile.

use crate::{
    Precompile, charge_input_cost, dispatch, mutate,
    storage::Handler,
    tip_fee_manager::{
        ITIPFeeAMM, TipFeeManager,
        amm::{M, MIN_LIQUIDITY, N, SCALE},
    },
    view,
};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IFeeManager;
impl Precompile for TipFeeManager {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IFeeManager::IFeeManagerCalls {
                    // IFeeManager view functions
                    userTokens(call) => view(call, |c| self.user_tokens(c)),
                    validatorTokens(call) => view(call, |c| self.get_validator_token(c.validator)),
                    collectedFees(call) => view(call, |c| self.collected_fees[c.validator][c.token].read()),

                    // IFeeManager mutate functions
                    setValidatorToken(call) => mutate(call, msg_sender, |sender, c| {
                        let beneficiary = self.storage.beneficiary();
                        self.set_validator_token(sender, c, beneficiary)
                    }),
                    setUserToken(call) => mutate(call, msg_sender, |sender, c| self.set_user_token(sender, c)),
                    distributeFees(call) => mutate(call, msg_sender, |_, c| {
                        self.distribute_fees(c.validator, c.token)
                    })

                }
                ITIPFeeAMM::ITIPFeeAMMCalls {
                    // ITIPFeeAMM metadata functions
                    M(call) => view(call, |_| Ok(M)),
                    N(call) => view(call, |_| Ok(N)),
                    SCALE(call) => view(call, |_| Ok(SCALE)),
                    MIN_LIQUIDITY(call) => view(call, |_| Ok(MIN_LIQUIDITY)),

                    // ITIPFeeAMM view functions
                    getPoolId(call) => view(call, |c| Ok(self.pool_id(c.userToken, c.validatorToken))),
                    getPool(call) => view(call, |c| Ok(self.get_pool(c)?.into())),
                    pools(call) => view(call, |c| Ok(self.pools[c.poolId].read()?.into())),
                    totalSupply(call) => view(call, |c| self.total_supply[c.poolId].read()),
                    liquidityBalances(call) => view(call, |c| self.liquidity_balances[c.poolId][c.user].read()),

                    // ITIPFeeAMM mutate functions
                    mint(call) => mutate(call, msg_sender, |sender, c| {
                        self.mint(sender, c.userToken, c.validatorToken, c.amountValidatorToken, c.to)
                    }),
                    burn(call) => mutate(call, msg_sender, |sender, c| {
                        let (amount_user_token, amount_validator_token) =
                            self.burn(sender, c.userToken, c.validatorToken, c.liquidity, c.to)?;
                        Ok(ITIPFeeAMM::burnReturn {
                            amountUserToken: amount_user_token,
                            amountValidatorToken: amount_validator_token,
                        })
                    }),
                    rebalanceSwap(call) => mutate(call, msg_sender, |sender, c| {
                        self.rebalance_swap(sender, c.userToken, c.validatorToken, c.amountOut, c.to)
                    })
                }
            }
        )
    }
}


