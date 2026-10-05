use crate::{
    error::{Result, TempoPrecompileError},
    storage::{ContractStorage, Handler, StorageAction, StorageCtx, StorageKey},
    tip_fee_manager::{ITIPFeeAMM, TIPFeeAMMError, TIPFeeAMMEvent, TipFeeManager},
    tip20::{ITIP20, TIP20Token, validate_usd_currency},
    tip403_registry::AuthRole,
};
use alloy::{
    primitives::{Address, B256, U256, keccak256, uint},
    sol_types::SolValue,
};
use tempo_precompiles_macros::Storable;

/// Fee multiplier for fee swaps: 0.9970 scaled by 10000 (30 bps fee).
pub const M: U256 = uint!(9970_U256);
/// Fee multiplier for rebalance swaps: 0.9985 scaled by 10000.
pub const N: U256 = uint!(9985_U256);
/// Scale factor for fixed-point AMM arithmetic (10000).
pub const SCALE: U256 = uint!(10000_U256);
/// Minimum liquidity locked permanently when initializing a pool.
pub const MIN_LIQUIDITY: U256 = uint!(1000_U256);

/// Computes the output amount for a fee swap: `amount_in * M / SCALE`.
///
/// # Errors
/// - `UnderOverflow` — multiplication of `amount_in * M` overflows
#[inline]
pub fn compute_amount_out(amount_in: U256) -> Result<U256> {
    amount_in
        .checked_mul(M)
        .map(|product| product / SCALE)
        .ok_or(TempoPrecompileError::under_overflow())
}

/// AMM pool reserves for a user-token / validator-token pair.
#[derive(Debug, Clone, Default, Storable)]
pub struct Pool {
    /// Reserve of the user's fee token.
    pub reserve_user_token: u128,
    /// Reserve of the validator's fee token.
    pub reserve_validator_token: u128,
}

impl From<Pool> for ITIPFeeAMM::Pool {
    fn from(value: Pool) -> Self {
        Self {
            reserveUserToken: value.reserve_user_token,
            reserveValidatorToken: value.reserve_validator_token,
        }
    }
}

/// Identifies a directional token pair in the fee AMM.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Storable)]
pub struct PoolKey {
    /// The fee token chosen by the user (transaction sender).
    pub user_token: Address,
    /// The fee token chosen by the validator (block producer).
    pub validator_token: Address,
}

impl Pool {
    /// Decodes a [`Pool`] from a raw EVM storage slot value (needed from changeset diffs).
    pub fn decode_from_slot(slot_value: U256) -> Self {
        use crate::storage::{LayoutCtx, Storable, packing::PackedSlot};

        // NOTE: fine to expect, as `StorageOps` on `PackedSlot` are infallible
        Self::load(&PackedSlot(slot_value), U256::ZERO, LayoutCtx::FULL)
            .expect("unable to decode Pool from slot")
    }

    /// Encodes a [`Pool`] into the raw EVM storage slot value.
    pub fn encode_to_slot(&self) -> Result<U256> {
        use crate::storage::packing::insert_into_word;

        let slot = insert_into_word(
            U256::ZERO,
            &self.reserve_user_token,
            __packing_pool::RESERVE_USER_TOKEN_LOC.offset_bytes,
            __packing_pool::RESERVE_USER_TOKEN_LOC.size,
        )?;
        let slot = insert_into_word(
            slot,
            &self.reserve_validator_token,
            __packing_pool::RESERVE_VALIDATOR_TOKEN_LOC.offset_bytes,
            __packing_pool::RESERVE_VALIDATOR_TOKEN_LOC.size,
        )?;
        Ok(slot)
    }

    /// Applies a fee swap to the pool.
    ///
    /// Checks `amount_out <= self.reserve_validator_token`, increments `self.reserve_user_token` by `amount_in`,
    /// and decrements `self.reserve_validator_token` by `amount_out`.
    pub fn apply_swap(&mut self, amount_in: U256, amount_out: U256) -> Result<()> {
        // Check if there's enough validatorToken available
        if amount_out > U256::from(self.reserve_validator_token) {
            return Err(TIPFeeAMMError::insufficient_liquidity().into());
        }

        let amount_in: u128 = amount_in
            .try_into()
            .map_err(|_| TempoPrecompileError::under_overflow())?;
        let amount_out: u128 = amount_out
            .try_into()
            .map_err(|_| TempoPrecompileError::under_overflow())?;

        // Update reserves
        self.reserve_user_token = self
            .reserve_user_token
            .checked_add(amount_in)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.reserve_validator_token = self
            .reserve_validator_token
            .checked_sub(amount_out)
            .ok_or_else(TempoPrecompileError::under_overflow)?;

        Ok(())
    }

    /// Returns whether the pool has enough reserve validator token to cover the given amount.
    pub fn has_enough_reserve_validator_token(&self, amount: U256) -> bool {
        U256::from(self.reserve_validator_token) >= amount
    }
}

impl PoolKey {
    /// Creates a new pool key from user and validator token addresses.
    /// This key uniquely identifies a trading pair in the AMM.
    pub fn new(user_token: Address, validator_token: Address) -> Self {
        Self {
            user_token,
            validator_token,
        }
    }

    /// Generates a unique pool ID by hashing the token pair addresses.
    /// Uses keccak256 to create a deterministic identifier for this pool.
    pub fn get_id(&self) -> B256 {
        keccak256((self.user_token, self.validator_token).abi_encode())
    }
}

/// AMM path [`TipFeeManager`] will take to swap `user_token` into `validator_token` for fee collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeRoute {
    /// User and validator share the same fee token; no swap is performed.
    SameToken,
    /// Direct pool `(user_token, validator_token)` swap.
    Direct,
    /// Two-hop swap (T5+): routes through `intermediate = userToken.quoteToken()`.
    /// Each hop applies the standard `M = 9970/10000` rate sequentially.
    TwoHop(Address),
}

/// Pools read during planning, paired with their observed validator-token reserve.
pub type PoolData = ((Address, Address), u128);

impl TipFeeManager {
    /// Returns the deterministic pool ID for a directional token pair. Note that the pool id is
    /// order-dependent: `(A, B)` produces a different ID than `(B, A)`.
    pub fn pool_id(&self, user_token: Address, validator_token: Address) -> B256 {
        PoolKey::new(user_token, validator_token).get_id()
    }

    /// Returns the [`Pool`] reserves for the given user/validator token pair.
    pub fn get_pool(&self, call: ITIPFeeAMM::getPoolCall) -> Result<Pool> {
        let pool_id = self.pool_id(call.userToken, call.validatorToken);
        self.pools[pool_id].read()
    }

    /// Reserves pool liquidity in transient storage for a pending fee swap.
    #[inline]
    pub fn reserve_pool_liquidity(&mut self, pool_id: B256, amount: u128) -> Result<()> {
        self.pending_fee_swap_reservation[pool_id].t_write(amount)
    }

    /// Executes a rebalance swap: sells `amount_out` of user-token from the pool in exchange for
    /// validator-token at the rebalance rate (`N / SCALE`). Used by arbitrageurs to rebalance reserves.
    ///
    /// # Errors
    /// - `InvalidAmount` — `amount_out` is zero or exceeds `u128`
    /// - `InsufficientReserves` — adding `amount_in` overflows the validator reserve
    /// - `InsufficientLiquidity` — remaining reserve would violate the pending reservation (T1C+)
    /// - `UnderOverflow` — arithmetic overflow computing `amount_in`
    pub fn rebalance_swap(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        amount_out: U256,
        to: Address,
    ) -> Result<U256> {
        if amount_out.is_zero() {
            return Err(TIPFeeAMMError::invalid_amount().into());
        }

        let pool_id = self.pool_id(user_token, validator_token);
        let mut pool = self.pools[pool_id].read()?;

        // Rebalancing swaps are always from validatorToken to userToken
        // Calculate input and update reserves
        let amount_in = amount_out
            .checked_mul(N)
            .and_then(|product| product.checked_div(SCALE))
            .and_then(|result| result.checked_add(U256::ONE))
            .ok_or(TempoPrecompileError::under_overflow())?;

        let amount_in: u128 = amount_in
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;
        let amount_out: u128 = amount_out
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;

        pool.reserve_validator_token = pool
            .reserve_validator_token
            .checked_add(amount_in)
            .ok_or(TIPFeeAMMError::insufficient_reserves())?;

        pool.reserve_user_token = pool
            .reserve_user_token
            .checked_sub(amount_out)
            .ok_or(TIPFeeAMMError::invalid_amount())?;

        if self.storage.spec().is_t1c() {
            let reserved = self.pending_fee_swap_reservation[pool_id].t_read()?;
            if pool.reserve_validator_token < reserved {
                return Err(TIPFeeAMMError::insufficient_liquidity().into());
            }
        }

        self.pools[pool_id].write(pool)?;

        let amount_in = U256::from(amount_in);
        let amount_out = U256::from(amount_out);
        let mut validator_token = TIP20Token::from_address(validator_token)?;
        validator_token.system_transfer_from(self.address, msg_sender, amount_in)?;

        // collect_fee_pre_tx creates FeeManager balance slots for free; do not convert them into storage credits.
        StorageCtx.set_tip1060_storage_credit_minting(false);
        let mut user_token = TIP20Token::from_address(user_token)?;
        user_token.transfer(
            self.address,
            ITIP20::transferCall {
                to,
                amount: amount_out,
            },
        )?;

        self.emit_event(TIPFeeAMMEvent::rebalance_swap(
            user_token.address(),
            validator_token.address(),
            msg_sender,
            amount_in,
            amount_out,
        ))?;

        Ok(amount_in)
    }

    /// Mints LP tokens by depositing validator-token into a pool.
    ///
    /// On first deposit the pool is initialized with equal reserves and [`MIN_LIQUIDITY`] is
    /// permanently locked. Subsequent deposits mint pro-rata to existing supply. Both tokens
    /// must be distinct, USD-denominated TIP-20s.
    ///
    /// NOTE: Validators who also provide liquidity have an information advantage over non-validator
    /// LPs. Because validators choose their preferred fee token and control transaction inclusion
    /// order as block producers, a validator-LP can predict which pool will receive fee-swap
    /// revenue and position liquidity accordingly.
    ///
    /// # Errors
    /// - `IdenticalAddresses` — `user_token` equals `validator_token`
    /// - `InvalidAmount` — `amount_validator_token` is zero or exceeds `u128`
    /// - `InvalidCurrency` — either token is not USD-denominated
    /// - `InsufficientLiquidity` — initial deposit ≤ `MIN_LIQUIDITY`, or zero liquidity minted
    /// - `InvalidSwapCalculation` — pro-rata arithmetic fails
    /// - `UnderOverflow` — supply or balance overflow
    pub fn mint(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        amount_validator_token: U256,
        to: Address,
    ) -> Result<U256> {
        if user_token == validator_token {
            return Err(TIPFeeAMMError::identical_addresses().into());
        }

        if amount_validator_token.is_zero() {
            return Err(TIPFeeAMMError::invalid_amount().into());
        }

        // Validate both tokens are USD currency
        validate_usd_currency(user_token)?;
        validate_usd_currency(validator_token)?;

        let user_token = TIP20Token::from_address(user_token)?;
        let mut validator_token = TIP20Token::from_address(validator_token)?;
        if self.storage.spec().is_t8() {
            user_token.ensure_authorized_as(&[
                (msg_sender, AuthRole::sender()),
                (self.address, AuthRole::recipient()),
                (to, AuthRole::recipient()),
            ])?;
            validator_token.ensure_authorized_as(&[(to, AuthRole::recipient())])?;
        }

        let pool_id = self.pool_id(user_token.address(), validator_token.address());
        let mut pool = self.pools[pool_id].read()?;
        let mut total_supply = self.get_total_supply(pool_id)?;

        let liquidity = if pool.reserve_user_token == 0 && pool.reserve_validator_token == 0 {
            let half_amount = amount_validator_token
                .checked_div(uint!(2_U256))
                .ok_or(TempoPrecompileError::under_overflow())?;

            if half_amount <= MIN_LIQUIDITY {
                return Err(TIPFeeAMMError::insufficient_liquidity().into());
            }

            total_supply = total_supply
                .checked_add(MIN_LIQUIDITY)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_total_supply(pool_id, total_supply)?;

            half_amount
                .checked_sub(MIN_LIQUIDITY)
                .ok_or(TIPFeeAMMError::insufficient_liquidity())?
        } else {
            // Subsequent deposits: mint as if user called rebalanceSwap then minted with both
            // liquidity = amountValidatorToken * _totalSupply / (V + n * U), with n = N / SCALE
            let product = N
                .checked_mul(U256::from(pool.reserve_user_token))
                .and_then(|product| product.checked_div(SCALE))
                .ok_or(TIPFeeAMMError::invalid_swap_calculation())?;

            let denom = U256::from(pool.reserve_validator_token)
                .checked_add(product)
                .ok_or(TIPFeeAMMError::invalid_amount())?;

            if denom.is_zero() {
                return Err(TIPFeeAMMError::division_by_zero().into());
            }

            amount_validator_token
                .checked_mul(total_supply)
                .and_then(|numerator| numerator.checked_div(denom))
                .ok_or(TIPFeeAMMError::invalid_swap_calculation())?
        };

        if liquidity.is_zero() {
            return Err(TIPFeeAMMError::insufficient_liquidity().into());
        }

        // Transfer validator tokens from user
        let _ = validator_token.system_transfer_from(
            self.address,
            msg_sender,
            amount_validator_token,
        )?;

        // Update reserves
        let validator_amount: u128 = amount_validator_token
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;

        pool.reserve_validator_token = pool
            .reserve_validator_token
            .checked_add(validator_amount)
            .ok_or(TIPFeeAMMError::invalid_amount())?;

        self.pools[pool_id].write(pool)?;

        // Mint LP tokens
        self.set_total_supply(
            pool_id,
            total_supply
                .checked_add(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        let balance = self.get_liquidity_balances(pool_id, to)?;
        self.set_liquidity_balances(
            pool_id,
            to,
            balance
                .checked_add(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // Emit Mint event
        self.emit_event(TIPFeeAMMEvent::mint(
            msg_sender,
            to,
            user_token.address(),
            validator_token.address(),
            amount_validator_token,
            liquidity,
        ))?;

        Ok(liquidity)
    }

    /// Burns LP tokens and returns the pro-rata share of both pool tokens to `to`.
    ///
    /// On T1C+ the burn is rejected if the remaining validator-token reserve would fall below
    /// the pending fee-swap reservation set by [`TipFeeManager::reserve_pool_liquidity`].
    ///
    /// # Errors
    /// - `IdenticalAddresses` — `user_token` equals `validator_token`
    /// - `InvalidAmount` — `liquidity` is zero or amounts exceed `u128`
    /// - `InvalidCurrency` — either token is not USD-denominated
    /// - `InsufficientLiquidity` — caller's balance < `liquidity`, or remaining reserve would
    ///   violate the pending reservation (T1C+)
    /// - `InsufficientReserves` — pool reserves underflow after withdrawal
    /// - `UnderOverflow` — supply or balance arithmetic overflows
    pub fn burn(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        liquidity: U256,
        to: Address,
    ) -> Result<(U256, U256)> {
        if user_token == validator_token {
            return Err(TIPFeeAMMError::identical_addresses().into());
        }

        if liquidity.is_zero() {
            return Err(TIPFeeAMMError::invalid_amount().into());
        }

        // Validate both tokens are USD currency
        validate_usd_currency(user_token)?;
        validate_usd_currency(validator_token)?;

        let mut user_token = TIP20Token::from_address(user_token)?;
        let mut validator_token = TIP20Token::from_address(validator_token)?;
        if self.storage.spec().is_t8() {
            user_token.ensure_authorized_as(&[(msg_sender, AuthRole::sender())])?;
            validator_token.ensure_authorized_as(&[(msg_sender, AuthRole::sender())])?;
        }

        let pool_id = self.pool_id(user_token.address(), validator_token.address());
        // Check user has sufficient liquidity
        let balance = self.get_liquidity_balances(pool_id, msg_sender)?;
        if balance < liquidity {
            return Err(TIPFeeAMMError::insufficient_liquidity().into());
        }

        let mut pool = self.pools[pool_id].read()?;
        // Calculate amounts to return
        let (amount_user_token, amount_validator_token) =
            self.calculate_burn_amounts(&pool, pool_id, liquidity)?;

        // T1C+: Check that burn leaves enough liquidity for pending fee swaps
        // Reservation is set by reserve_pool_liquidity() in collect_fee_pre_tx
        let validator_amount: u128 = amount_validator_token
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;
        let available_after_burn = pool
            .reserve_validator_token
            .checked_sub(validator_amount)
            .ok_or(TIPFeeAMMError::insufficient_reserves())?;
        if self.storage.spec().is_t1c() {
            let reserved = self.pending_fee_swap_reservation[pool_id].t_read()?;
            if available_after_burn < reserved {
                return Err(TIPFeeAMMError::insufficient_liquidity().into());
            }
        }

        // Burn LP tokens
        self.set_liquidity_balances(
            pool_id,
            msg_sender,
            balance
                .checked_sub(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;
        let total_supply = self.get_total_supply(pool_id)?;
        self.set_total_supply(
            pool_id,
            total_supply
                .checked_sub(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // Update reserves with underflow checks
        let user_amount: u128 = amount_user_token
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;
        let validator_amount: u128 = amount_validator_token
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;

        pool.reserve_user_token = pool
            .reserve_user_token
            .checked_sub(user_amount)
            .ok_or(TIPFeeAMMError::insufficient_reserves())?;
        pool.reserve_validator_token = pool
            .reserve_validator_token
            .checked_sub(validator_amount)
            .ok_or(TIPFeeAMMError::insufficient_reserves())?;
        self.pools[pool_id].write(pool)?;

        // Transfer tokens to user
        let _ = user_token.transfer(
            self.address,
            ITIP20::transferCall {
                to,
                amount: amount_user_token,
            },
        )?;

        let _ = validator_token.transfer(
            self.address,
            ITIP20::transferCall {
                to,
                amount: amount_validator_token,
            },
        )?;

        // Emit Burn event
        self.emit_event(TIPFeeAMMEvent::burn(
            msg_sender,
            user_token.address(),
            validator_token.address(),
            amount_user_token,
            amount_validator_token,
            liquidity,
            to,
        ))?;

        Ok((amount_user_token, amount_validator_token))
    }

    /// Calculate burn amounts for liquidity withdrawal
    fn calculate_burn_amounts(
        &self,
        pool: &Pool,
        pool_id: B256,
        liquidity: U256,
    ) -> Result<(U256, U256)> {
        let total_supply = self.get_total_supply(pool_id)?;
        let amount_user_token = liquidity
            .checked_mul(U256::from(pool.reserve_user_token))
            .and_then(|product| product.checked_div(total_supply))
            .ok_or(TempoPrecompileError::under_overflow())?;
        let amount_validator_token = liquidity
            .checked_mul(U256::from(pool.reserve_validator_token))
            .and_then(|product| product.checked_div(total_supply))
            .ok_or(TempoPrecompileError::under_overflow())?;

        Ok((amount_user_token, amount_validator_token))
    }

    /// Plans the AMM path needed to swap `max_amount` of `user_token` into `validator_token`
    /// under the active hardfork. Read-only; does not reserve.
    ///
    /// On T5+ falls back to a two-hop path through `userToken.quoteToken()` as per [TIP-1033].
    /// Returns `(route, queried_intermediate, pools)`:
    /// - `route` is `None` when no path has sufficient liquidity.
    /// - `queried_intermediate` is `Some(addr)` whenever `userToken.quoteToken()` was read,
    ///   regardless of whether the value is usable. Callers can cache it to skip the cold
    ///   storage read on subsequent admissions.
    /// - `pools` lists every pool slot read during planning, paired with its observed reserve.
    ///
    /// # Errors
    /// - `InvalidToken` — `user_token` does not have a valid TIP-20 prefix
    /// - `UnderOverflow` — fee-amount arithmetic overflows
    ///
    /// [TIP-1033]: <https://docs.tempo.xyz/protocol/tips/tip-1033>
    pub fn plan_fee_route(
        &self,
        user_token: Address,
        validator_token: Address,
        max_amount: U256,
    ) -> Result<(Option<FeeRoute>, Option<Address>, Vec<PoolData>)> {
        let mut data = Vec::new();

        if user_token == validator_token {
            return Ok((Some(FeeRoute::SameToken), None, data));
        }

        let actions = self.storage.actions();

        actions.unrecorded(|| {
            let amount_out = compute_amount_out(max_amount)?;

            // Direct (single-hop) path — always checked.
            let direct_slot = &self.pools[self.pool_id(user_token, validator_token)];
            let direct = direct_slot.read()?;
            data.push((
                (user_token, validator_token),
                direct.reserve_validator_token,
            ));
            let has_enough_liquidity = direct.has_enough_reserve_validator_token(amount_out);
            actions.record_always(StorageAction::FeeAmmLiquidityCheck(
                direct_slot.as_slot().slot(),
                direct.encode_to_slot()?,
                amount_out,
                has_enough_liquidity,
            ));
            if has_enough_liquidity {
                return Ok((Some(FeeRoute::Direct), None, data));
            }

            // T5+: two-hop fallback through `userToken.quoteToken()`.
            if !self.storage.spec().is_t5() {
                return Ok((None, None, data));
            }

            // TIP-20 token graph forbids self-quoting, so `intermediate == user_token` is unreachable.
            let mid_token =
                actions.recorded(|| TIP20Token::from_address(user_token)?.quote_token())?;
            if mid_token.is_zero() || mid_token == validator_token {
                return Ok((None, Some(mid_token), data));
            }

            // First leg: user_token -> intermediate.
            let leg1_slot = &self.pools[self.pool_id(user_token, mid_token)];
            let leg1 = leg1_slot.read()?;
            data.push(((user_token, mid_token), leg1.reserve_validator_token));
            let has_enough_liquidity = leg1.has_enough_reserve_validator_token(amount_out);
            actions.record_always(StorageAction::FeeAmmLiquidityCheck(
                leg1_slot.as_slot().slot(),
                leg1.encode_to_slot()?,
                amount_out,
                has_enough_liquidity,
            ));
            if !has_enough_liquidity {
                return Ok((None, Some(mid_token), data));
            }

            // Second leg: intermediate -> validator_token.
            let amount_out2 = compute_amount_out(amount_out)?;
            let leg2_slot = &self.pools[self.pool_id(mid_token, validator_token)];
            let leg2 = leg2_slot.read()?;
            data.push(((mid_token, validator_token), leg2.reserve_validator_token));
            let has_enough_liquidity = leg2.has_enough_reserve_validator_token(amount_out2);
            actions.record_always(StorageAction::FeeAmmLiquidityCheck(
                leg2_slot.as_slot().slot(),
                leg2.encode_to_slot()?,
                amount_out2,
                has_enough_liquidity,
            ));
            if !has_enough_liquidity {
                return Ok((None, Some(mid_token), data));
            }

            Ok((Some(FeeRoute::TwoHop(mid_token)), Some(mid_token), data))
        })
    }

    /// Executes a fee swap, converting `user_token` to `validator_token` at a fixed rate m = 0.997
    /// Called internally by [`TipFeeManager::collect_fee_post_tx`] during post-tx fee collection.
    ///
    /// # Errors
    /// - `InsufficientLiquidity` — pool validator-token reserve is below the required output
    /// - `UnderOverflow` — reserve arithmetic overflows or amounts exceed `u128`
    pub fn execute_fee_swap(
        &mut self,
        user_token: Address,
        validator_token: Address,
        amount_in: U256,
    ) -> Result<U256> {
        let actions = self.storage.actions();
        // We suppress the actions recording to instead emit a single `FeeAmmSwap` action
        actions.unrecorded(|| {
            // Calculate output at fixed price m = 0.9970
            let amount_out = compute_amount_out(amount_in)?;

            let pool_id = self.pool_id(user_token, validator_token);
            let mut pool = self.pools[pool_id].read()?;
            let pool_slot = pool.encode_to_slot()?;
            pool.apply_swap(amount_in, amount_out)?;
            self.pools[pool_id].write(pool)?;

            actions.record_always(StorageAction::FeeAmmSwap(
                pool_id.mapping_slot(self.pools.slot()),
                pool_slot,
                amount_in,
            ));

            Ok(amount_out)
        })
    }

    /// Returns the total supply of LP tokens for the given pool.
    pub fn get_total_supply(&self, pool_id: B256) -> Result<U256> {
        self.total_supply[pool_id].read()
    }

    /// Set total supply of LP tokens for a pool
    fn set_total_supply(&mut self, pool_id: B256, total_supply: U256) -> Result<()> {
        self.total_supply[pool_id].write(total_supply)
    }

    /// Returns the LP token balance for `user` in the given pool.
    pub fn get_liquidity_balances(&self, pool_id: B256, user: Address) -> Result<U256> {
        self.liquidity_balances[pool_id][user].read()
    }

    /// Set user's LP token balance
    fn set_liquidity_balances(
        &mut self,
        pool_id: B256,
        user: Address,
        balance: U256,
    ) -> Result<()> {
        self.liquidity_balances[pool_id][user].write(balance)
    }
}


