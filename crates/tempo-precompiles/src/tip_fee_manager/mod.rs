//! [Fee manager] precompile for transaction fee collection, distribution, and token swaps.
//!
//! [Fee manager]: <https://docs.tempo.xyz/protocol/fees>

pub mod amm;
pub mod dispatch;

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping, StorageCtx},
    tip_fee_manager::amm::{FeeRoute, Pool, compute_amount_out},
    tip20::{ITIP20, TIP20Token, validate_usd_currency},
    tip20_factory::TIP20Factory,
    tip403_registry::AuthRole,
};
use alloy::primitives::{Address, B256, U256, uint};
pub use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, FeeManagerError, FeeManagerEvent, IFeeManager, ITIPFeeAMM,
    TIP_FEE_MANAGER_ADDRESS, TIPFeeAMMError, TIPFeeAMMEvent,
};
use tempo_precompiles_macros::contract;

/// Fee manager precompile that handles transaction fee collection and distribution.
///
/// Users and validators choose their preferred TIP-20 fee token. When they differ, fees are
/// swapped through the built-in AMM (`TIPFeeAMM`).
///
/// The struct fields define the on-chain storage layout; the `#[contract]` macro generates the
/// storage handlers which provide an ergonomic way to interact with the EVM state.
#[contract(addr = TIP_FEE_MANAGER_ADDRESS)]
pub struct TipFeeManager {
    validator_tokens: Mapping<Address, Address>,
    user_tokens: Mapping<Address, Address>,
    collected_fees: Mapping<Address, Mapping<Address, U256>>,
    pools: Mapping<B256, Pool>,
    total_supply: Mapping<B256, U256>,
    liquidity_balances: Mapping<B256, Mapping<Address, U256>>,

    // WARNING(rusowsky): transient storage slots must always be placed at the very end until the `contract`
    // macro is refactored and has 2 independent layouts (persistent and transient).
    // If new (persistent) storage fields need to be added to the precompile, they must go above this one.
    /// T1C+: Tracks liquidity reserved for a pending fee swap during `collect_fee_pre_tx`.
    /// Checked by `burn` and `rebalance_swap` to prevent withdrawals that would violate the reservation.
    pending_fee_swap_reservation: Mapping<B256, u128>,

    /// T5+: Intermediate token for two-hop fee swap routing ([TIP-1033]).
    /// Set by `collect_fee_pre_tx` when the direct `(userToken, validatorToken)` pool has
    /// insufficient liquidity and the swap falls back through `userToken.quoteToken()`.
    ///
    /// [TIP-1033]: <https://docs.tempo.xyz/protocol/tips/tip-1033>
    two_hop_intermediate: Address,
}

impl TipFeeManager {
    /// Swap fee in basis points (0.25%).
    pub const FEE_BPS: u64 = 25;
    /// Basis-point denominator (10 000 = 100%).
    pub const BASIS_POINTS: u64 = 10000;
    /// Minimum TIP-20 balance required for fee operations (1e9).
    pub const MINIMUM_BALANCE: U256 = uint!(1_000_000_000_U256);

    /// Initializes the fee manager precompile.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Returns the validator's preferred fee token, falling back to [`DEFAULT_FEE_TOKEN`].
    pub fn get_validator_token(&self, beneficiary: Address) -> Result<Address> {
        let token = self.validator_tokens[beneficiary].read()?;

        if token.is_zero() {
            Ok(DEFAULT_FEE_TOKEN)
        } else {
            Ok(token)
        }
    }

    /// Sets the caller's preferred fee token as a validator.
    ///
    /// Rejects the call if `sender` is the current block's beneficiary (prevents mid-block
    /// fee-token changes) or if the token is not a valid USD-denominated TIP-20 registered in
    /// [`TIP20Factory`].
    ///
    /// # Errors
    /// - `InvalidToken` — token is not a deployed TIP-20 in [`TIP20Factory`]
    /// - `CannotChangeWithinBlock` — `sender` equals the current block `beneficiary`
    /// - `InvalidCurrency` — token is not USD-denominated
    pub fn set_validator_token(
        &mut self,
        sender: Address,
        call: IFeeManager::setValidatorTokenCall,
        beneficiary: Address,
    ) -> Result<()> {
        // Validate that the token is a valid deployed TIP20
        if !TIP20Factory::new().is_tip20(call.token)? {
            return Err(FeeManagerError::invalid_token().into());
        }

        // Prevent changing within the validator's own block
        if sender == beneficiary {
            return Err(FeeManagerError::cannot_change_within_block().into());
        }

        // Validate that the fee token is USD
        validate_usd_currency(call.token)?;

        self.validator_tokens[sender].write(call.token)?;

        // Emit ValidatorTokenSet event
        self.emit_event(FeeManagerEvent::validator_token_set(sender, call.token))
    }

    /// Sets the caller's preferred fee token as a user. Must be a valid USD-denominated TIP-20
    /// registered in [`TIP20Factory`].
    ///
    /// # Errors
    /// - `InvalidToken` — token is not a deployed TIP-20 in [`TIP20Factory`]
    /// - `InvalidCurrency` — token is not USD-denominated
    pub fn set_user_token(
        &mut self,
        sender: Address,
        call: IFeeManager::setUserTokenCall,
    ) -> Result<()> {
        // Validate that the token is a valid deployed TIP20
        if !TIP20Factory::new().is_tip20(call.token)? {
            return Err(FeeManagerError::invalid_token().into());
        }

        // Validate that the fee token is USD
        validate_usd_currency(call.token)?;

        // T3+: skip write and event if the token is already set to the requested value.
        // Prevents permissionless callers from forcing redundant pool invalidation scans.
        if self.storage.spec().is_t3() {
            let current = self.user_tokens[sender].read()?;
            if current == call.token {
                return Ok(());
            }
        }

        self.user_tokens[sender].write(call.token)?;

        // Emit UserTokenSet event
        self.emit_event(FeeManagerEvent::user_token_set(sender, call.token))
    }

    /// Collects fees from `fee_payer` before transaction execution.
    ///
    /// Transfers `max_amount` of `user_token` to the fee manager via [`TIP20Token`] and, if the
    /// validator prefers a different token, verifies sufficient pool liquidity.
    /// Reserves liquidity on T1C+, with a two-hop fallback through `userToken.quoteToken()` on T5+.
    /// Returns the user's fee token and the validator fee token.
    ///
    /// # Errors
    /// - `InvalidToken` — `user_token` does not have a valid TIP-20 prefix
    /// - `PolicyForbids` — TIP-403 policy rejects the fee token transfer
    /// - `InsufficientLiquidity` — AMM pool lacks liquidity for the fee swap (T5+: with two-hop fallback)
    pub fn collect_fee_pre_tx(
        &mut self,
        fee_payer: Address,
        user_token: Address,
        max_amount: U256,
        beneficiary: Address,
        skip_liquidity_check: bool,
    ) -> Result<Address> {
        // Get the validator's token preference
        let validator_token = self.get_validator_token(beneficiary)?;

        let mut tip20_token = TIP20Token::from_address(user_token)?;

        // TIP-1042: T8 fee collection exempts FeeManager recipient authorization.
        if self.storage.spec().is_t8() {
            tip20_token.ensure_authorized_as(&[(fee_payer, AuthRole::sender())])?;
        } else {
            tip20_token.ensure_transfer_authorized(fee_payer, self.address)?;
        }
        tip20_token.transfer_fee_pre_tx(fee_payer, max_amount)?;

        if !skip_liquidity_check {
            let (route, ..) = self.plan_fee_route(user_token, validator_token, max_amount)?;
            let route = route.ok_or_else(TIPFeeAMMError::insufficient_liquidity)?;
            self.reserve_fee_liquidity(user_token, validator_token, max_amount, route)?;
        }

        // Return the user's token preference
        Ok(user_token)
    }

    /// Reserves AMM liquidity needed to settle the selected fee route after transaction execution.
    fn reserve_fee_liquidity(
        &mut self,
        user_token: Address,
        validator_token: Address,
        max_amount: U256,
        route: FeeRoute,
    ) -> Result<()> {
        match route {
            FeeRoute::SameToken => {}
            FeeRoute::Direct if self.storage.spec().is_t1c() => {
                let amount_out: u128 = compute_amount_out(max_amount)?
                    .try_into()
                    .map_err(|_| TempoPrecompileError::under_overflow())?;
                self.reserve_pool_liquidity(self.pool_id(user_token, validator_token), amount_out)?;
            }
            FeeRoute::Direct => {}
            FeeRoute::TwoHop(intermediate) => {
                // T5+ implies T1C+, so reservation is always required here.
                let out1: u128 = compute_amount_out(max_amount)?
                    .try_into()
                    .map_err(|_| TempoPrecompileError::under_overflow())?;
                let out2: u128 = compute_amount_out(U256::from(out1))?
                    .try_into()
                    .map_err(|_| TempoPrecompileError::under_overflow())?;
                self.reserve_pool_liquidity(self.pool_id(user_token, intermediate), out1)?;
                self.reserve_pool_liquidity(self.pool_id(intermediate, validator_token), out2)?;
                self.two_hop_intermediate.t_write(intermediate)?;
            }
        }

        Ok(())
    }

    /// Finalizes fee collection after transaction execution.
    ///
    /// Refunds unused `user_token` to `fee_payer` via [`TIP20Token`], executes the fee swap
    /// through the AMM pool if tokens differ, and accumulates fees for the validator. Returns
    /// the validator-credited amount (post-feeAMM haircut, in the validator's fee token), which
    /// is used by the payload builder to score blocks by actual proposer revenue.
    ///
    /// # Errors
    /// - `InvalidToken` — `fee_token` does not have a valid TIP-20 prefix
    /// - `InsufficientLiquidity` — AMM pool lacks liquidity for the fee swap
    /// - `UnderOverflow` — collected-fee accumulator overflows
    pub fn collect_fee_post_tx(
        &mut self,
        fee_payer: Address,
        actual_spending: U256,
        refund_amount: U256,
        fee_token: Address,
        beneficiary: Address,
    ) -> Result<U256> {
        // Refund unused tokens to user
        let mut tip20_token = TIP20Token::from_address(fee_token)?;
        tip20_token.transfer_fee_post_tx(fee_payer, refund_amount, actual_spending)?;

        // Execute fee swap and track collected fees
        let hop_token = self.two_hop_intermediate.t_read()?;
        let validator_token = self.get_validator_token(beneficiary)?;

        let amount = if fee_token == validator_token {
            actual_spending
        } else if hop_token.is_zero() {
            // Single-hop (direct) swap
            if !actual_spending.is_zero() {
                self.execute_fee_swap(fee_token, validator_token, actual_spending)?;
            }
            compute_amount_out(actual_spending)?
        } else {
            // Two-hop swap (only in T5+): each hop applies M = 9970/10000 sequentially
            if !actual_spending.is_zero() {
                let out1 = self.execute_fee_swap(fee_token, hop_token, actual_spending)?;
                self.execute_fee_swap(hop_token, validator_token, out1)?;
            }
            compute_amount_out(compute_amount_out(actual_spending)?)?
        };

        self.increment_collected_fees(beneficiary, validator_token, amount)?;

        Ok(amount)
    }

    /// Increment collected fees for a specific validator and token combination.
    fn increment_collected_fees(
        &mut self,
        validator: Address,
        token: Address,
        amount: U256,
    ) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }

        self.collected_fees[validator][token].sinc(amount)?;

        Ok(())
    }

    /// Transfers a validator's accumulated fee balance to their address via [`TIP20Token`] and
    /// zeroes the ledger. No-ops when the balance is zero.
    ///
    /// # Errors
    /// - `InvalidToken` — `token` does not have a valid TIP-20 prefix
    pub fn distribute_fees(&mut self, validator: Address, token: Address) -> Result<()> {
        // collect_fee_pre_tx creates FeeManager balance slots for free; do not convert them into storage credits.
        StorageCtx.set_tip1060_storage_credit_minting(false);

        let amount = self.collected_fees[validator][token].read()?;
        if amount.is_zero() {
            return Ok(());
        }
        self.collected_fees[validator][token].write(U256::ZERO)?;

        // Transfer fees to validator
        let mut tip20_token = TIP20Token::from_address(token)?;
        tip20_token.transfer(
            self.address,
            ITIP20::transferCall {
                to: validator,
                amount,
            },
        )?;

        // Emit FeesDistributed event
        self.emit_event(FeeManagerEvent::fees_distributed(validator, token, amount))?;

        Ok(())
    }

    /// Reads the stored fee token preference for a user.
    pub fn user_tokens(&self, call: IFeeManager::userTokensCall) -> Result<Address> {
        self.user_tokens[call.user].read()
    }
}


