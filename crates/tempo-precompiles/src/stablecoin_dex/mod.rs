//! On-chain CLOB (Central Limit Order Book) for [stablecoin trading].
//!
//! Supports limit orders, market swaps, and flip orders across
//! TIP-20 token pairs with tick-based pricing and price-time priority.
//!
//! [stablecoin trading]: <https://docs.tempo.xyz/protocol/exchange>

pub mod dispatch;
pub mod error;
pub mod order;
pub mod orderbook;

pub use order::Order;
use order::OrderMapping;
use orderbook::BookId;
pub use orderbook::{
    MAX_TICK, MIN_TICK, OrderStep, Orderbook, PRICE_SCALE, RoundingDirection, TickLevel,
    base_to_quote, quote_to_base, step_exact_in, step_exact_out, taker_output, tick_to_price,
    validate_tick_spacing,
};
use tempo_contracts::precompiles::PATH_USD_ADDRESS;
pub use tempo_contracts::precompiles::{IStablecoinDEX, StablecoinDEXError, StablecoinDEXEvents};

use crate::{
    STABLECOIN_DEX_ADDRESS,
    error::{Result, TempoPrecompileError},
    stablecoin_dex::orderbook::{
        Fill, MAX_PRICE, MIN_PRICE, compute_book_key, walk_resting_orders,
    },
    storage::{Handler, Mapping},
    storage_credits::{StorageCreditDeltas, StorageCredits},
    tip20::{ITIP20, TIP20Token, validate_usd_currency},
    tip20_factory::TIP20Factory,
    tip403_registry::{AuthRole, TIP403Registry, is_policy_lookup_error},
};
use alloy::primitives::{Address, B256, U256};
use tempo_precompiles_macros::contract;
use tempo_primitives::TempoAddressExt;

/// Minimum order size of $100 USD
pub const MIN_ORDER_AMOUNT: u128 = 100_000_000;

/// Allowed tick spacing for order placement
pub const TICK_SPACING: i16 = 10;

/// On-chain CLOB (Central Limit Order Book) for stablecoin trading.
///
/// Supports limit orders, market swaps, and flip orders across USD-denominated TIP-20 token pairs.
/// Orders use tick-based pricing with price-time priority.
///
/// The struct fields define the on-chain storage layout; the `#[contract]` macro generates the
/// storage handlers which provide an ergonomic way to interact with the EVM state.
#[contract(addr = STABLECOIN_DEX_ADDRESS)]
pub struct StablecoinDEX {
    books: Mapping<B256, Orderbook>,
    orders: OrderMapping,
    balances: Mapping<Address, Mapping<Address, u128>>,
    next_order_id: u128,
    book_keys: Vec<B256>,
    dex_storage_credits: Mapping<Address, u64>,
}

impl StablecoinDEX {
    /// Returns the [`StablecoinDEX`] address.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Initializes the stablecoin DEX precompile.
    pub fn initialize(&mut self) -> Result<()> {
        // must ensure the account is not empty, by setting some code
        self.__initialize()
    }

    /// Read next order ID (always at least 1)
    fn next_order_id(&self) -> Result<u128> {
        Ok(self.next_order_id.read()?.max(1))
    }

    /// Increment next order ID
    fn increment_next_order_id(&mut self) -> Result<()> {
        let next_order_id = self.next_order_id()?;
        self.next_order_id.write(next_order_id + 1)
    }

    /// Returns the user's DEX balance for `token`.
    pub fn balance_of(&self, user: Address, token: Address) -> Result<u128> {
        self.balances[user][token].read()
    }

    /// Returns the number of reusable order storage credits owned by `user`.
    pub fn storage_credits(&self, user: Address) -> Result<u64> {
        self.dex_storage_credits[user].read()
    }

    /// Adds reusable-order storage credits for `user`.
    fn credit_dex_storage_slots(&mut self, user: Address, slots: u64) -> Result<()> {
        if slots == 0 || !self.storage.spec().is_t7() {
            return Ok(());
        }

        let current = self.dex_storage_credits[user].read()?;
        let updated = current.saturating_add(slots);

        if current != 0 {
            return self.dex_storage_credits[user].write(updated);
        }

        // Initializing this counter spends one DEX-owned credit from the newly granted slots.
        // We still store the full logical balance: the DEX balance is one credit short while the
        // counter exists, then gets that credit back when the counter is cleared.
        let mut storage_credits = StorageCredits::new();
        let (_, delta) = storage_credits.with_budget(self.address, 1, || {
            self.dex_storage_credits[user].write(updated)
        })?;

        if delta != -1 {
            return Err(TempoPrecompileError::Fatal(format!(
                "DEX storage credit bookkeeping spend mismatch: reserved 1, delta {delta}"
            )));
        }

        Ok(())
    }

    /// Deletes an order and returns the number of DEX TIP-1060 credits minted.
    fn delete_order(&mut self, order: &Order) -> Result<u64> {
        StorageCredits::new()
            .track_minted_credits(self.address, || self.orders[order.order_id()].delete())
            .map(|(_, credits)| credits)
    }

    /// Rewrites an order and returns the number of DEX TIP-1060 credits minted.
    fn rewrite_order(&mut self, order: Order, id: BookId) -> Result<u64> {
        StorageCredits::new()
            .track_minted_credits(self.address, || {
                self.orders[order.order_id()].write_in_book(order, id)
            })
            .map(|(_, credits)| credits)
    }

    /// Updates an unlinked neighbor order-record and credits its maker for any minted credits.
    fn unlink_neighbor_and_credit_maker(
        &mut self,
        order_id: u128,
        update: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<()> {
        let (_, credits) =
            StorageCredits::new().track_minted_credits(self.address, || update(self))?;
        if credits == 0 {
            return Ok(());
        }

        let maker = self.orders[order_id].maker()?;
        self.credit_dex_storage_slots(maker, credits)
    }

    /// Deletes an order and tracks the maker's minted DEX TIP-1060 credits for deferred flush.
    fn delete_order_and_track_deltas(
        &mut self,
        storage_credits: &mut StorageCreditDeltas,
        order: &Order,
    ) -> Result<()> {
        let credits = self.delete_order(order)?;
        storage_credits.credit_slots(order.maker(), credits);
        Ok(())
    }

    /// Writes a reusable order record while spending at most the maker's DEX storage credits.
    ///
    /// Credits are scoped to the physical `Order` record. Shared book metadata writes performed by
    /// `commit_order_to_book` remain outside this budget and stay in preserve mode.
    fn write_order_spending_dex_storage_credits(&mut self, order: Order, id: BookId) -> Result<()> {
        let user = order.maker();
        let user_credits = self.dex_storage_credits[user].read()?;
        if user_credits == 0 {
            return self.orders[order.order_id()].write_in_book(order, id);
        }

        // Clear the user's bookkeeping slot before writing the order record. This makes the
        // TIP-1060 credit represented by that bookkeeping slot available to the direct budget.
        self.dex_storage_credits[user].delete()?;

        let mut storage_credits = StorageCredits::new();
        let (_, delta) = storage_credits.with_budget(self.address, user_credits, || {
            self.orders[order.order_id()].write_in_book(order, id)
        })?;
        let spent_credits = if delta < 0 { (-delta) as u64 } else { 0 };

        self.credit_dex_storage_slots(user, user_credits.saturating_sub(spent_credits))?;

        Ok(())
    }

    /// Returns the minimum representable scaled price (`MIN_PRICE`).
    pub fn min_price(&self) -> u32 {
        MIN_PRICE
    }

    /// Returns the maximum representable scaled price (`MAX_PRICE`).
    pub fn max_price(&self) -> u32 {
        MAX_PRICE
    }

    /// Validates that a trading pair exists or creates the pair
    fn validate_or_create_pair(&mut self, book: &Orderbook, token: Address) -> Result<()> {
        if !book.is_initialized() {
            self.create_pair(token)?;
        }
        Ok(())
    }

    /// Fetches an active [`Order`] from storage by ID.
    ///
    /// # Errors
    /// - `OrderDoesNotExist` — order has a zero maker (already filled/deleted) or has not yet
    ///   been assigned (ID ≥ next order ID)
    pub fn get_order(&self, order_id: u128) -> Result<Order> {
        let order = self.orders[order_id].read()?;

        // If the order is not filled and currently active
        if !order.maker().is_zero() && order.order_id() < self.next_order_id()? {
            Ok(order)
        } else {
            Err(StablecoinDEXError::order_does_not_exist().into())
        }
    }

    /// Set user's balance for a specific token
    fn set_balance(&mut self, user: Address, token: Address, amount: u128) -> Result<()> {
        self.balances[user][token].write(amount)
    }

    /// Add to user's balance
    fn increment_balance(&mut self, user: Address, token: Address, amount: u128) -> Result<()> {
        let current = self.balance_of(user, token)?;
        self.set_balance(
            user,
            token,
            current
                .checked_add(amount)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )
    }

    /// Subtract from user's balance.
    fn sub_balance(&mut self, user: Address, token: Address, amount: u128) -> Result<()> {
        let current = self.balance_of(user, token)?;
        self.set_balance(
            user,
            token,
            current
                .checked_sub(amount)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )
    }

    /// Emit the appropriate OrderFilled event
    fn emit_order_filled(
        &mut self,
        order_id: u128,
        maker: Address,
        taker: Address,
        amount_filled: u128,
        partial_fill: bool,
    ) -> Result<()> {
        self.emit_event(StablecoinDEXEvents::order_filled(
            order_id,
            maker,
            taker,
            amount_filled,
            partial_fill,
        ))?;

        Ok(())
    }

    /// Transfer tokens, accounting for pathUSD
    fn transfer(&mut self, token: Address, to: Address, amount: u128) -> Result<()> {
        TIP20Token::from_address(token)?.transfer(
            self.address,
            ITIP20::transferCall {
                to,
                amount: U256::from(amount),
            },
        )?;
        Ok(())
    }

    /// Transfer tokens from user, accounting for pathUSD
    fn transfer_from(&mut self, token: Address, sender: Address, amount: u128) -> Result<()> {
        if self.storage.spec().is_t5() {
            TIP20Token::from_address(token)?.system_transfer_from(
                self.address,
                sender,
                U256::from(amount),
            )?;
        } else {
            TIP20Token::from_address(token)?.transfer_from(
                self.address,
                ITIP20::transferFromCall {
                    from: sender,
                    to: self.address,
                    amount: U256::from(amount),
                },
            )?;
        }
        Ok(())
    }

    /// Decrement user's internal balance or transfer from external wallet.
    ///
    /// When `check_pause` is true and the full amount is covered by internal balance,
    /// verifies the token is not paused (T4+). Callers that already check pause state
    /// (e.g. swaps via `validate_and_build_route`) should pass `false` to avoid a
    /// redundant SLOAD.
    fn decrement_balance_or_transfer_from(
        &mut self,
        sender: Address,
        token: Address,
        amount: u128,
        check_pause: bool,
    ) -> Result<()> {
        // Ensure that the token can be transferred
        let tip20 = TIP20Token::from_address(token)?;
        tip20.ensure_transfer_authorized(sender, self.address)?;

        let user_balance = self.balance_of(sender, token)?;
        if user_balance >= amount {
            // When fully covered by internal balance, TIP-20 transferFrom won't run,
            // so we must check the pause state ourselves (spec: T4+).
            if check_pause && self.storage.spec().is_t4() {
                tip20.check_not_paused()?;
            }
            self.sub_balance(sender, token, amount)
        } else {
            let remaining = amount
                .checked_sub(user_balance)
                .ok_or(TempoPrecompileError::under_overflow())?;

            self.transfer_from(token, sender, remaining)?;
            self.set_balance(sender, token, 0)
        }
    }

    /// Quotes the input amount required to receive exactly `amount_out` tokens, routing through
    /// one or more orderbooks without executing trades.
    ///
    /// # Errors
    /// - `IdenticalTokens` — `token_in` and `token_out` are the same address
    /// - `InvalidToken` — a token address does not have a valid TIP-20 prefix
    /// - `PairDoesNotExist` — no orderbook exists for one of the hops in the route
    /// - `InsufficientLiquidity` — not enough resting orders to fill `amount_out`
    pub fn quote_swap_exact_amount_out(
        &self,
        token_in: Address,
        token_out: Address,
        amount_out: u128,
    ) -> Result<u128> {
        // Find and validate the trade route (book keys + direction for each hop)
        let route = self.find_trade_path(token_in, token_out)?;

        // Execute quotes backwards from output to input
        let mut current_amount = amount_out;
        for (book_key, base_for_quote) in route.iter().rev() {
            current_amount = self.quote_exact_out(*book_key, current_amount, *base_for_quote)?;
        }

        Ok(current_amount)
    }

    /// Quotes the output amount received for exactly `amount_in` input tokens, routing through
    /// one or more orderbooks without executing trades.
    ///
    /// # Errors
    /// - `IdenticalTokens` — `token_in` and `token_out` are the same address
    /// - `InvalidToken` — a token address does not have a valid TIP-20 prefix
    /// - `PairDoesNotExist` — no orderbook exists for one of the hops in the route
    /// - `InsufficientLiquidity` — not enough resting orders to fill `amount_in`
    pub fn quote_swap_exact_amount_in(
        &self,
        token_in: Address,
        token_out: Address,
        amount_in: u128,
    ) -> Result<u128> {
        // Find and validate the trade route (book keys + direction for each hop)
        let route = self.find_trade_path(token_in, token_out)?;

        // Execute quotes for each hop using precomputed book keys and directions
        let mut current_amount = amount_in;
        for (book_key, base_for_quote) in route {
            current_amount = self.quote_exact_in(book_key, current_amount, base_for_quote)?;
        }

        Ok(current_amount)
    }

    /// Swaps `amount_in` of `token_in` for `token_out`, routing through
    /// one or more orderbooks. Deducts input via [`TIP20Token`] transfer
    /// or DEX balance, then fills orders at best price per hop.
    ///
    /// # Errors
    /// - `InvalidBaseToken` — token address does not have a valid TIP-20 prefix
    /// - `PairNotFound` — no orderbook exists for the token pair
    /// - `InsufficientOutput` — final output amount falls below `min_amount_out`
    /// - `InsufficientBalance` — sender balance lower than required input
    pub fn swap_exact_amount_in(
        &mut self,
        sender: Address,
        token_in: Address,
        token_out: Address,
        amount_in: u128,
        min_amount_out: u128,
    ) -> Result<u128> {
        // Find and validate the trade route (book keys + direction for each hop)
        let route = self.find_trade_path(token_in, token_out)?;

        // Deduct input tokens from sender (only once, at the start)
        // Pause already checked in validate_and_build_route
        self.decrement_balance_or_transfer_from(sender, token_in, amount_in, false)?;

        // Execute swaps for each hop - intermediate balances are transitory
        let mut amount = amount_in;
        let mut storage_credits = StorageCreditDeltas::new();
        for (book_key, base_for_quote) in route {
            // Fill orders for this hop - no min check on intermediate hops
            amount = self.fill_orders_exact_in(
                &mut storage_credits,
                book_key,
                base_for_quote,
                amount,
                sender,
            )?;
        }

        // Check final output meets minimum requirement
        if amount < min_amount_out {
            return Err(StablecoinDEXError::insufficient_output().into());
        }

        self.transfer(token_out, sender, amount)?;
        storage_credits.flush(|user, slots| self.credit_dex_storage_slots(user, slots))?;

        Ok(amount)
    }

    /// Swaps to receive exactly `amount_out` of `token_out`, routing
    /// through one or more orderbooks. Works backwards from output to
    /// compute input, then deducts via [`TIP20Token`] or DEX balance.
    ///
    /// # Errors
    /// - `InvalidBaseToken` — token address does not have a valid TIP-20 prefix
    /// - `PairNotFound` — no orderbook exists for the token pair
    /// - `MaxInputExceeded` — required input exceeds `max_amount_in`
    /// - `InsufficientBalance` — sender balance lower than required input
    pub fn swap_exact_amount_out(
        &mut self,
        sender: Address,
        token_in: Address,
        token_out: Address,
        amount_out: u128,
        max_amount_in: u128,
    ) -> Result<u128> {
        // Find and validate the trade route (book keys + direction for each hop)
        let route = self.find_trade_path(token_in, token_out)?;

        // Work backwards from output to calculate input needed - intermediate amounts are TRANSITORY
        let mut amount = amount_out;
        let mut storage_credits = StorageCreditDeltas::new();
        for (book_key, base_for_quote) in route.iter().rev() {
            amount = self.fill_orders_exact_out(
                &mut storage_credits,
                *book_key,
                *base_for_quote,
                amount,
                sender,
            )?;
        }

        if amount > max_amount_in {
            return Err(StablecoinDEXError::max_input_exceeded().into());
        }

        // Deduct input tokens ONCE at end
        // Pause already checked in validate_and_build_route
        self.decrement_balance_or_transfer_from(sender, token_in, amount, false)?;

        // Transfer only final output ONCE at end
        self.transfer(token_out, sender, amount_out)?;
        storage_credits.flush(|user, slots| self.credit_dex_storage_slots(user, slots))?;

        Ok(amount)
    }

    /// Returns the [`TickLevel`] for a given `base` token, `tick`, and side. Looks up the
    /// quote token via [`TIP20Token`] and derives the book key.
    ///
    /// # Errors
    /// - `InvalidBaseToken` — `base` address does not resolve to a valid [`TIP20Token`]
    pub fn get_price_level(&self, base: Address, tick: i16, is_bid: bool) -> Result<TickLevel> {
        let quote = TIP20Token::from_address(base)?.quote_token()?;
        let book_key = compute_book_key(base, quote);
        let mut level = if is_bid {
            self.books[book_key].bids[tick].read()?
        } else {
            self.books[book_key].asks[tick].read()?
        };

        if self.storage.spec().is_t12() {
            // Sum the remaining amount of every order reachable from the tick's head.
            let mut order_id = level.links.head;
            level.total_liquidity = 0;
            while order_id != 0 {
                let order = self.orders[order_id].read_in_book(book_key)?;
                level.total_liquidity = level
                    .total_liquidity
                    .checked_add(order.remaining())
                    .ok_or(TempoPrecompileError::under_overflow())?;
                order_id = order.next();
            }
        }

        Ok(level)
    }

    /// Returns the [`Orderbook`] for a given pair key.
    pub fn books(&self, pair_key: B256) -> Result<Orderbook> {
        self.books[pair_key].read()
    }

    /// Returns all registered orderbook keys.
    pub fn get_book_keys(&self) -> Result<Vec<B256>> {
        self.book_keys.read()
    }

    /// Returns the zero-based `book_keys` index persisted for `book_key`, if one is set.
    pub(crate) fn book_key_index(&self, book_key: B256) -> Result<Option<u32>> {
        let book = self.books[book_key].read()?;
        if !book.is_initialized() {
            return Err(StablecoinDEXError::pair_does_not_exist().into());
        }
        Ok(book.id().index())
    }

    /// Resolves a book key by index from the append-only `book_keys` vector.
    pub fn book_key_for_index(&self, index: u32) -> Result<B256> {
        self.book_keys
            .at(index as usize)?
            .ok_or_else(StablecoinDEXError::pair_does_not_exist)?
            .read()
    }

    /// Persists the `book_keys` vector index for an existing orderbook.
    pub fn set_book_index(&mut self, index: u32) -> Result<()> {
        let book_key = self.book_key_for_index(index)?;
        if let Some(current_index) = self.book_key_index(book_key)? {
            if index == current_index {
                return Ok(());
            }
            return Err(StablecoinDEXError::index_already_set().into());
        }

        self.books[book_key]
            .book_id
            .write(*BookId::from_index(index))
    }

    /// Converts a relative tick to a scaled price. On T2+ validates [`TICK_SPACING`] alignment.
    ///
    /// # Errors
    /// - `InvalidTick` — tick is not aligned to [`TICK_SPACING`] (T2+ only)
    pub fn tick_to_price(&self, tick: i16) -> Result<u32> {
        if self.storage.spec().is_t2() {
            orderbook::validate_tick_spacing(tick)?;
        }

        Ok(orderbook::tick_to_price(tick))
    }

    /// Converts a scaled price to a relative tick. On T2+ validates [`TICK_SPACING`] alignment.
    ///
    /// # Errors
    /// - `TickOutOfBounds` — price is outside the `[MIN_PRICE, MAX_PRICE]` range
    /// - `InvalidTick` — resulting tick is not aligned to [`TICK_SPACING`] (T2+ only)
    pub fn price_to_tick(&self, price: u32) -> Result<i16> {
        let tick = orderbook::price_to_tick(price)?;

        if self.storage.spec().is_t2() {
            orderbook::validate_tick_spacing(tick)?;
        }

        Ok(tick)
    }

    /// Creates a new trading pair between `base` and its quote token.
    /// Both must be USD-denominated tokens validated via
    /// [`TIP20Factory`]. Reverts if the pair already exists.
    ///
    /// # Errors
    /// - `InvalidBaseToken` — token address does not have a valid TIP-20 prefix
    /// - `InvalidCurrency` — both tokens must be USD-denominated (validated via [`TIP20Factory`]).
    /// - `PairAlreadyExists` — an orderbook for this pair is already initialized
    pub fn create_pair(&mut self, base: Address) -> Result<B256> {
        // Validate that base is a TIP20 token
        if !TIP20Factory::new().is_tip20(base)? {
            return Err(StablecoinDEXError::invalid_base_token().into());
        }

        let quote = TIP20Token::from_address(base)?.quote_token()?;
        validate_usd_currency(base)?;
        validate_usd_currency(quote)?;

        let book_key = compute_book_key(base, quote);

        if self.books[book_key].read()?.is_initialized() {
            return Err(StablecoinDEXError::pair_already_exists().into());
        }

        let book = if self.storage.spec().is_t8() {
            Orderbook::new_with_index(base, quote, self.book_keys.len()? as u32)
        } else {
            Orderbook::new(base, quote)
        };
        self.books[book_key].write(book)?;
        self.book_keys.push(book_key)?;

        // Emit PairCreated event
        self.emit_event(StablecoinDEXEvents::pair_created(book_key, base, quote))?;

        Ok(book_key)
    }

    /// Places a limit order on the orderbook for `token` against its quote token.
    /// Escrows the appropriate amount via [`TIP20Token`] transfer or DEX balance and enforces
    /// compliance via the [`TIP403Registry`]. Auto-creates the trading pair if needed.
    ///
    /// # Errors
    /// - `InvalidBaseToken` — token address does not have a valid TIP-20 prefix
    /// - `TickOutOfBounds` — tick is outside the allowed `[MIN_TICK, MAX_TICK]` range
    /// - `InvalidTick` — tick is not aligned to `TICK_SPACING`
    /// - `BelowMinimumOrderSize` — order amount is below `MIN_ORDER_AMOUNT`
    /// - `InsufficientBalance` — sender balance lower than required
    /// - `PolicyForbids` — TIP-403 policy rejects the token transfer
    ///
    /// # Returns
    /// The assigned order ID
    pub fn place(
        &mut self,
        sender: Address,
        token: Address,
        amount: u128,
        is_bid: bool,
        tick: i16,
    ) -> Result<u128> {
        let quote_token = TIP20Token::from_address(token)?.quote_token()?;

        // Compute book_key from token pair
        let book_key = compute_book_key(token, quote_token);

        let book = self.books[book_key].read()?;
        self.validate_or_create_pair(&book, token)?;

        // Validate tick is within bounds
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinDEXError::tick_out_of_bounds(tick).into());
        }

        // Enforce that the tick adheres to tick spacing
        if tick % TICK_SPACING != 0 {
            return Err(StablecoinDEXError::invalid_tick().into());
        }

        // Validate order amount meets minimum requirement
        if amount < MIN_ORDER_AMOUNT {
            return Err(StablecoinDEXError::below_minimum_order_size(amount).into());
        }

        // Calculate escrow amount and token based on order side
        let (escrow_token, escrow_amount, non_escrow_token) = if is_bid {
            // For bids, escrow quote tokens based on price
            let quote_amount = base_to_quote(amount, tick, RoundingDirection::Up)
                .ok_or(StablecoinDEXError::insufficient_balance())?;
            (quote_token, quote_amount, token)
        } else {
            // For asks, escrow base tokens
            (token, amount, quote_token)
        };

        // Check policy on non-escrow token (escrow token is checked in decrement_balance_or_transfer_from)
        // Direction: DEX → sender (order placer receives non-escrow token when filled)
        let non_escrow_tip20 = TIP20Token::from_address(non_escrow_token)?;
        non_escrow_tip20.ensure_transfer_authorized(self.address, sender)?;

        // On T4+, reject if the non-escrow token is paused. When this order fills, the
        // non-escrow token may be moved via internal-balance updates that bypass TIP-20's
        // pause check, so we enforce it at placement.
        if self.storage.spec().is_t4() {
            non_escrow_tip20.check_not_paused()?;
        }

        // Debit from user's balance or transfer from wallet
        self.decrement_balance_or_transfer_from(sender, escrow_token, escrow_amount, true)?;

        // Create the order
        let order_id = self.next_order_id()?;
        self.increment_next_order_id()?;
        let order = if is_bid {
            Order::new_bid(order_id, sender, book_key, amount, tick)
        } else {
            Order::new_ask(order_id, sender, book_key, amount, tick)
        };
        self.commit_order_to_book(order, true)?;

        // Emit OrderPlaced event
        self.emit_event(StablecoinDEXEvents::order_placed(
            order_id, sender, token, amount, is_bid, tick, false, 0,
        ))?;

        Ok(order_id)
    }

    /// Commits an order to the specified orderbook, updating tick bits, best bid/ask, and total liquidity.
    ///
    /// On T7+, `charge_credits` spends maker credits. Keep it `false` for taker-triggered flips
    /// so takers cannot consume the maker's credit balance.
    fn commit_order_to_book(&mut self, mut order: Order, charge_credits: bool) -> Result<()> {
        let orderbook = self.books[order.book_key()].read()?;
        let book_id = orderbook.id();
        let mut level = self.books[order.book_key()]
            .tick_level_handler(order.tick(), order.is_bid())
            .read()?;

        let prev_tail = level.links.tail;
        if prev_tail == 0 {
            level.links.head = order.order_id();
            level.links.tail = order.order_id();

            self.books[order.book_key()].set_tick_bit(order.tick(), order.is_bid())?;

            if order.is_bid() {
                if order.tick() > orderbook.best_bid_tick {
                    self.books[order.book_key()]
                        .best_bid_tick
                        .write(order.tick())?;
                }
            } else if order.tick() < orderbook.best_ask_tick {
                self.books[order.book_key()]
                    .best_ask_tick
                    .write(order.tick())?;
            }
        } else {
            // Update previous tail's next pointer.
            if self.storage.spec().is_t8() {
                self.orders[prev_tail].next()?.write(order.order_id())?;
            } else {
                let mut prev_order = self.orders[prev_tail].read_in_book(order.book_key())?;
                prev_order.next = order.order_id();
                self.orders[prev_tail].write_in_book(prev_order, book_id)?;
            }

            // Set current order's prev pointer
            order.prev = prev_tail;
            level.links.tail = order.order_id();
        }

        if !self.storage.spec().is_t12() {
            level.total_liquidity = level
                .total_liquidity
                .checked_add(order.remaining())
                .ok_or(TempoPrecompileError::under_overflow())?;
        }

        self.books[order.book_key()]
            .tick_level_handler_mut(order.tick(), order.is_bid())
            .write(level)?;

        match (charge_credits, self.storage.spec()) {
            // User placements: T7+ can spend maker credits for new reusable order storage.
            (true, spec) if spec.is_t7() => {
                self.write_order_spending_dex_storage_credits(order, book_id)
            }
            // T8+ flip rewrites credit deleted order slots without spending maker credits.
            (false, spec) if spec.is_t8() => {
                let (maker, credits) = (order.maker(), self.rewrite_order(order, book_id)?);
                self.credit_dex_storage_slots(maker, credits)
            }
            // Pre-T7 has no DEX credits; T7 non-charged writes never change credits behavior.
            _ => self.orders[order.order_id()].write_in_book(order, book_id),
        }
    }

    /// Places a flip order that auto-reverses to the opposite side when
    /// fully filled, acting as perpetual liquidity. Escrows tokens via
    /// [`TIP20Token`] and enforces compliance via [`TIP403Registry`].
    /// Pre-T5: for bids `flip_tick` must be > `tick`; for asks, < `tick`.
    /// T5+ (TIP-1030): for bids `flip_tick >= tick`; for asks `flip_tick <= tick`.
    ///
    /// # Errors
    /// - `InvalidBaseToken` — token address does not have a valid TIP-20 prefix
    /// - `TickOutOfBounds` — tick or flip_tick outside `[MIN_TICK, MAX_TICK]`
    /// - `InvalidTick` — tick is not aligned to `TICK_SPACING`
    /// - `InvalidFlipTick` — flip_tick on wrong side of tick for order direction
    /// - `BelowMinimumOrderSize` — order amount is below `MIN_ORDER_AMOUNT`
    /// - `InsufficientBalance` — sender balance lower than required escrow
    /// - `PolicyForbids` — TIP-403 policy rejects the token transfer
    #[allow(clippy::too_many_arguments)]
    pub fn place_flip(
        &mut self,
        sender: Address,
        token: Address,
        amount: u128,
        is_bid: bool,
        tick: i16,
        flip_tick: i16,
        internal_balance_only: bool,
    ) -> Result<u128> {
        let quote_token = TIP20Token::from_address(token)?.quote_token()?;

        // Compute book_key from token pair
        let book_key = compute_book_key(token, quote_token);

        // CHECKPOINT START: `place_flip` performs multiple state mutations that
        // must succeed or fail as a unit. The guard auto-reverts on drop.
        let batch = self.storage.checkpoint();

        // Check book existence
        let book = self.books[book_key].read()?;
        self.validate_or_create_pair(&book, token)?;

        // Validate tick and flip_tick are within bounds
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinDEXError::tick_out_of_bounds(tick).into());
        }

        // Enforce that the tick adheres to tick spacing
        if tick % TICK_SPACING != 0 {
            return Err(StablecoinDEXError::invalid_tick().into());
        }

        if !(MIN_TICK..=MAX_TICK).contains(&flip_tick) {
            return Err(StablecoinDEXError::tick_out_of_bounds(flip_tick).into());
        }

        // Enforce that the tick adheres to tick spacing
        if flip_tick % TICK_SPACING != 0 {
            return Err(StablecoinDEXError::invalid_flip_tick().into());
        }

        // Validate flip_tick relationship to tick based on order side.
        // TIP-1030 (T5): allow flip_tick == tick for same-tick flip orders.
        // NOTE: `Order::new_flip` performs the same check defensively below; the early
        // check here is preserved to keep error semantics backwards-compatible
        // (invalid flip_tick fails with `invalid_flip_tick` before any escrow logic).
        if (flip_tick == tick && !self.storage.spec().is_t5())
            || (is_bid && flip_tick < tick)
            || (!is_bid && flip_tick > tick)
        {
            return Err(StablecoinDEXError::invalid_flip_tick().into());
        }

        // Validate order amount meets minimum requirement
        if amount < MIN_ORDER_AMOUNT {
            return Err(StablecoinDEXError::below_minimum_order_size(amount).into());
        }

        // Calculate escrow amount and token based on order side
        let (escrow_token, escrow_amount, non_escrow_token) = if is_bid {
            // For bids, escrow quote tokens based on price
            let quote_amount = base_to_quote(amount, tick, RoundingDirection::Up)
                .ok_or(StablecoinDEXError::insufficient_balance())?;
            (quote_token, quote_amount, token)
        } else {
            // For asks, escrow base tokens
            (token, amount, quote_token)
        };

        // Check policy on non-escrow token (escrow token is checked in decrement_balance_or_transfer_from or below)
        // Direction: DEX → sender (order placer receives non-escrow token when filled)
        let non_escrow_tip20 = TIP20Token::from_address(non_escrow_token)?;
        non_escrow_tip20.ensure_transfer_authorized(self.address, sender)?;

        // On T4+, reject if the non-escrow token is paused. When this order fills, the
        // non-escrow token may be moved via internal-balance updates that bypass TIP-20's
        // pause check, so we enforce it at placement.
        if self.storage.spec().is_t4() {
            non_escrow_tip20.check_not_paused()?;
        }

        // Debit from user's balance only. This is set to true after a flip order is filled and the
        // subsequent flip order is being placed.
        if internal_balance_only {
            let tip20 = TIP20Token::from_address(escrow_token)?;
            tip20.ensure_transfer_authorized(sender, self.address)?;
            // Internal-balance-only path bypasses TIP-20 transferFrom,
            // so we must check the pause state ourselves (spec: T4+).
            if self.storage.spec().is_t4() {
                tip20.check_not_paused()?;
            }
            let user_balance = self.balance_of(sender, escrow_token)?;
            if user_balance < escrow_amount {
                return Err(StablecoinDEXError::insufficient_balance().into());
            }
            self.sub_balance(sender, escrow_token, escrow_amount)?;
        } else {
            self.decrement_balance_or_transfer_from(sender, escrow_token, escrow_amount, true)?;
        }

        // Create the flip order
        let order_id = self.next_order_id()?;
        let order = Order::new_flip(
            order_id,
            sender,
            book_key,
            amount,
            tick,
            is_bid,
            flip_tick,
            self.storage.spec(),
        )
        .map_err(|_| StablecoinDEXError::invalid_flip_tick())?;

        // Commit the flip order
        if self.storage.spec().is_t1c() {
            // PERF: skip 1 redundant SLOAD
            self.next_order_id.write(order_id + 1)?;
        } else {
            self.increment_next_order_id()?;
        }
        self.commit_order_to_book(order, true)?;

        // Emit OrderPlaced event for flip order
        self.emit_event(StablecoinDEXEvents::order_placed(
            order_id, sender, token, amount, is_bid, tick, true, flip_tick,
        ))?;

        // CHECKPOINT END: commit the state-changing batch
        batch.commit();

        Ok(order_id)
    }

    fn flip_in_place(
        &mut self,
        order: &Order,
        base_token: Address,
        quote_token: Address,
    ) -> Result<()> {
        // CHECKPOINT START: `flip_in_place` performs multiple state mutations that
        // must succeed or fail as a unit. The guard auto-reverts on drop.
        let batch = self.storage.checkpoint();

        // Prepare the flipped order
        let flipped = order.create_flipped_order(order.order_id);

        // Calculate escrow amount and token based on order side
        let (escrow_token, escrow_amount, non_escrow_token) = if flipped.is_bid {
            // For bids, escrow quote tokens based on price
            let quote_amount = base_to_quote(flipped.amount, flipped.tick, RoundingDirection::Up)
                .ok_or(StablecoinDEXError::insufficient_balance())?;
            (quote_token, quote_amount, base_token)
        } else {
            // For asks, escrow base tokens
            (base_token, flipped.amount, quote_token)
        };

        let user_balance = self.balance_of(flipped.maker, escrow_token)?;
        if user_balance < escrow_amount {
            return Err(StablecoinDEXError::insufficient_balance().into());
        }

        // Check policy and pause state on escrow token
        // Direction: maker → DEX
        let escrow_tip20 = TIP20Token::from_address(escrow_token)?;
        escrow_tip20.check_not_paused()?;
        escrow_tip20.ensure_transfer_authorized(flipped.maker, self.address)?;

        // Check policy and pause state on non-escrow token
        // Direction: DEX → maker (order placer receives non-escrow token when filled)
        let non_escrow_tip20 = TIP20Token::from_address(non_escrow_token)?;
        non_escrow_tip20.check_not_paused()?;
        non_escrow_tip20.ensure_transfer_authorized(self.address, flipped.maker)?;

        self.sub_balance(flipped.maker, escrow_token, escrow_amount)?;

        debug_assert_eq!(order.order_id(), flipped.order_id());
        debug_assert_eq!(order.book_key(), flipped.book_key());
        // In-place flips are taker-triggered, so don't spend maker credits.
        self.commit_order_to_book(flipped, false)?;

        // Emit OrderFlipped event for flip order
        self.emit_event(StablecoinDEXEvents::OrderFlipped(
            IStablecoinDEX::OrderFlipped {
                orderId: flipped.order_id,
                maker: flipped.maker,
                token: base_token,
                amount: flipped.amount,
                isBid: flipped.is_bid,
                tick: flipped.tick,
                flipTick: flipped.flip_tick,
            },
        ))?;

        // CHECKPOINT END: commit the state-changing batch
        batch.commit();

        Ok(())
    }

    /// Partially fill an order with the specified amount. Fill amount is denominated in base token.
    fn partial_fill_order(
        &mut self,
        order: &mut Order,
        level: &mut TickLevel,
        fill_amount: u128,
        taker: Address,
    ) -> Result<()> {
        let orderbook = self.books[order.book_key()].read()?;

        // Update order remaining amount
        let new_remaining = order.remaining() - fill_amount;
        self.orders[order.order_id()]
            .remaining()?
            .write(new_remaining)?;
        order.remaining = new_remaining;

        if order.is_bid() {
            // Bid order maker receives base tokens (exact amount).
            self.increment_balance(order.maker(), orderbook.base, fill_amount)?;
        } else {
            // Ask order maker receives quote tokens, rounded up to favor the maker.
            let quote_amount = base_to_quote(fill_amount, order.tick(), RoundingDirection::Up)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.increment_balance(order.maker(), orderbook.quote, quote_amount)?;
        }

        // Update price level total liquidity
        if !self.storage.spec().is_t12() {
            level.total_liquidity = level
                .total_liquidity
                .checked_sub(fill_amount)
                .ok_or(TempoPrecompileError::under_overflow())?;

            self.books[order.book_key()]
                .tick_level_handler_mut(order.tick(), order.is_bid())
                .write(*level)?;
        }

        // Emit OrderFilled event for partial fill
        self.emit_order_filled(order.order_id(), order.maker(), taker, fill_amount, true)?;

        Ok(())
    }

    /// Fill an order and delete from storage. Returns the next best order and price level.
    ///
    /// NOTE: Maker transfer policy is not enforced here to not block swaps on the pair.
    /// Note that TIP403 checks on order placement and withdraws are enforced.
    /// [`cancel_stale_order`](Self::cancel_stale_order) can be used to remove orders.
    fn fill_order(
        &mut self,
        storage_credits: &mut StorageCreditDeltas,
        book_key: B256,
        order: &mut Order,
        mut level: TickLevel,
        taker: Address,
    ) -> Result<Option<(TickLevel, Order)>> {
        debug_assert_eq!(order.book_key(), book_key);

        let orderbook = self.books[book_key].read()?;
        let fill_amount = order.remaining();

        // Maker settlement: bid maker receives base (exact), ask maker receives quote
        // rounded UP to favor the maker.
        if order.is_bid() {
            self.increment_balance(order.maker(), orderbook.base, fill_amount)?;
        } else {
            let quote_amount = base_to_quote(fill_amount, order.tick(), RoundingDirection::Up)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.increment_balance(order.maker(), orderbook.quote, quote_amount)?;
        }

        // Emit OrderFilled event for complete fill
        self.emit_order_filled(order.order_id(), order.maker(), taker, fill_amount, false)?;

        if order.is_flip() {
            // Create a new flip order with flipped side and swapped ticks.
            // Bid becomes Ask, Ask becomes Bid.
            // The current tick becomes the new flip_tick, and flip_tick becomes the new tick.
            // Uses internal balance only, does not transfer from wallet.
            let res = if self.storage.spec().is_t5() {
                // Post T5: flip the order in place, without creating a new one.
                self.flip_in_place(order, orderbook.base, orderbook.quote)
            } else {
                self.place_flip(
                    order.maker(),
                    orderbook.base,
                    order.amount(),
                    !order.is_bid(),
                    order.flip_tick(),
                    order.tick(),
                    true,
                )
                .map(|_| ())
            };

            // Business logic errors are ignored so that flip failure does not block the swap.
            // System errors (OOG, DB errors, panics) propagate because state may be inconsistent.
            if let Err(err) = &res {
                if err.is_system_error() && self.storage.spec().is_t1a() {
                    return Err(res.unwrap_err());
                }

                if self.storage.spec().is_t5() {
                    self.emit_event(StablecoinDEXEvents::flip_failed(
                        order.order_id(),
                        order.maker(),
                        err.selector(),
                    ))?;
                }
            }

            // T5+: a successful `flip_in_place` already rewrote the order
            // record under the same `orderId` (TIP-1056). In every other case
            // (pre-T5, or T5 with a swallowed flip failure) the filled order
            // record must be deleted to avoid leaving an orphan in storage.
            let keep_record = self.storage.spec().is_t5() && res.is_ok();
            if !keep_record {
                self.delete_order_and_track_deltas(storage_credits, order)?;
            }
        } else {
            // Non-flip filled order: always delete.
            self.delete_order_and_track_deltas(storage_credits, order)?;
        }

        // Advance tick if liquidity is exhausted
        let next_tick_info = if order.next() == 0 {
            self.books[book_key]
                .tick_level_handler_mut(order.tick(), order.is_bid())
                .delete()?;
            self.books[book_key].delete_tick_bit(order.tick(), order.is_bid())?;

            let (tick, has_liquidity) =
                self.books[book_key].next_initialized_tick(order.tick(), order.is_bid())?;

            // Update best_tick when tick is exhausted
            if order.is_bid() {
                let new_best = if has_liquidity { tick } else { i16::MIN };
                self.books[book_key].best_bid_tick.write(new_best)?;
            } else {
                let new_best = if has_liquidity { tick } else { i16::MAX };
                self.books[book_key].best_ask_tick.write(new_best)?;
            }

            if !has_liquidity {
                // No more liquidity at better prices - return None to signal completion
                None
            } else {
                let new_level = self.books[book_key]
                    .tick_level_handler(tick, order.is_bid())
                    .read()?;
                let new_order = self.orders[new_level.links.head].read_in_book(book_key)?;

                Some((new_level, new_order))
            }
        } else {
            // If there are subsequent orders at tick, advance to next order
            level.links.head = order.next();
            let (_, credits) = StorageCredits::new().track_minted_credits(self.address, || {
                self.orders[order.next()].prev()?.delete()
            })?;

            if !self.storage.spec().is_t12() {
                level.total_liquidity = level
                    .total_liquidity
                    .checked_sub(fill_amount)
                    .ok_or(TempoPrecompileError::under_overflow())?;
            }

            self.books[book_key]
                .tick_level_handler_mut(order.tick(), order.is_bid())
                .write(level)?;

            let new_order = self.orders[order.next()].read_in_book(book_key)?;
            storage_credits.credit_slots(new_order.maker(), credits);

            Some((level, new_order))
        };

        Ok(next_tick_info)
    }

    /// Fill orders for exact output amount
    fn fill_orders_exact_out(
        &mut self,
        storage_credits: &mut StorageCreditDeltas,
        book_key: B256,
        is_bid: bool,
        amount_out: u128,
        taker: Address,
    ) -> Result<u128> {
        let mut level = self.get_best_price_level(book_key, is_bid)?;
        let order = self.orders[level.links.head].read_in_book(book_key)?;

        // Returns the total input spent to receive `amount_out`.
        walk_resting_orders(order, amount_out, is_bid, step_exact_out, |order, fill| {
            self.settle_fill(storage_credits, book_key, taker, &mut level, order, fill)
        })
    }

    /// Fill orders with exact amount in
    fn fill_orders_exact_in(
        &mut self,
        storage_credits: &mut StorageCreditDeltas,
        book_key: B256,
        is_bid: bool,
        amount_in: u128,
        taker: Address,
    ) -> Result<u128> {
        let mut level = self.get_best_price_level(book_key, is_bid)?;
        let order = self.orders[level.links.head].read_in_book(book_key)?;

        // Returns the total output received for spending `amount_in`.
        walk_resting_orders(order, amount_in, is_bid, step_exact_in, |order, fill| {
            self.settle_fill(storage_credits, book_key, taker, &mut level, order, fill)
        })
    }

    /// Applies one order fill during swap execution and returns the next order to
    /// fill, or `None` when this order terminates the trade. Shared by the
    /// exact-in and exact-out swap walks so their settlement cannot diverge.
    fn settle_fill(
        &mut self,
        storage_credits: &mut StorageCreditDeltas,
        book_key: B256,
        taker: Address,
        level: &mut TickLevel,
        mut order: Order,
        fill: Fill,
    ) -> Result<Option<Order>> {
        match fill {
            Fill::Partial(fill_amount) => {
                self.partial_fill_order(&mut order, level, fill_amount, taker)?;
                Ok(None)
            }
            Fill::Full => {
                let next = self.fill_order(storage_credits, book_key, &mut order, *level, taker)?;
                match next {
                    Some((new_level, new_order)) => {
                        *level = new_level;
                        Ok(Some(new_order))
                    }
                    None => Ok(None),
                }
            }
        }
    }

    /// Helper function to get best tick from orderbook
    fn get_best_price_level(&self, book_key: B256, is_bid: bool) -> Result<TickLevel> {
        let orderbook = self.books[book_key].read()?;

        let current_tick = if is_bid {
            if orderbook.best_bid_tick == i16::MIN {
                return Err(StablecoinDEXError::insufficient_liquidity().into());
            }
            orderbook.best_bid_tick
        } else {
            if orderbook.best_ask_tick == i16::MAX {
                return Err(StablecoinDEXError::insufficient_liquidity().into());
            }
            orderbook.best_ask_tick
        };

        self.books[book_key]
            .tick_level_handler(current_tick, is_bid)
            .read()
    }

    /// Read-only traversal to the order that execution would fill after fully
    /// consuming `order`, mirroring the advancement inside [`Self::fill_order`]:
    /// stay on the same tick while more orders are linked, otherwise jump to the
    /// next initialized tick. Returns `None` when no further liquidity exists.
    ///
    /// Used by the per-order quote paths so quotes walk the book exactly like a
    /// swap does. Uses the order's in-memory `next`/`tick` (unchanged by a fill).
    fn next_order_after(
        &self,
        book_key: B256,
        order: &Order,
        is_bid: bool,
    ) -> Result<Option<Order>> {
        if order.next() != 0 {
            return Ok(Some(self.orders[order.next()].read_in_book(book_key)?));
        }

        let (next_tick, has_liquidity) =
            self.books[book_key].next_initialized_tick(order.tick(), is_bid)?;
        if !has_liquidity {
            return Ok(None);
        }

        let next_level = self.books[book_key]
            .tick_level_handler(next_tick, is_bid)
            .read()?;
        self.orders[next_level.links.head]
            .read_in_book(book_key)
            .map(Some)
    }

    /// Cancels an active order and refunds escrowed tokens to the maker.
    /// Only the order maker can cancel their own orders.
    ///
    /// # Errors
    /// - `OrderDoesNotExist` — order ID not found or already fully filled
    /// - `Unauthorized` — only the order maker can cancel their order
    pub fn cancel(&mut self, sender: Address, order_id: u128) -> Result<()> {
        let order = self.orders[order_id].read()?;

        if order.maker().is_zero() {
            return Err(StablecoinDEXError::order_does_not_exist().into());
        }

        if order.maker() != sender {
            return Err(StablecoinDEXError::unauthorized().into());
        }

        if order.remaining() == 0 {
            return Err(StablecoinDEXError::order_does_not_exist().into());
        }

        self.cancel_active_order(order)
    }

    /// Cancel an active order (already in the orderbook)
    fn cancel_active_order(&mut self, order: Order) -> Result<()> {
        let mut level = self.books[order.book_key()]
            .tick_level_handler(order.tick(), order.is_bid())
            .read()?;

        // Update linked list
        if order.prev() != 0 {
            self.unlink_neighbor_and_credit_maker(order.prev(), |s| {
                s.orders[order.prev()].next()?.write(order.next())
            })?;
        } else {
            level.links.head = order.next();
        }

        if order.next() != 0 {
            self.unlink_neighbor_and_credit_maker(order.next(), |s| {
                s.orders[order.next()].prev()?.write(order.prev())
            })?;
        } else {
            level.links.tail = order.prev();
        }

        let has_level_changed = if self.storage.spec().is_t12() {
            // +T12: Only cancelling the head or tail changes tick-level storage.
            order.prev() == 0 || order.next() == 0
        } else {
            // pre-T12: Every cancellation changes the maintained liquidity aggregate.
            level.total_liquidity = level
                .total_liquidity
                .checked_sub(order.remaining())
                .ok_or(TempoPrecompileError::under_overflow())?;
            true
        };

        // If this was the last order at this tick, clear the bitmap bit
        if level.links.head == 0 {
            self.books[order.book_key()].delete_tick_bit(order.tick(), order.is_bid())?;

            // If this was the best tick, update it
            let orderbook = self.books[order.book_key()].read()?;
            let best_tick = if order.is_bid() {
                orderbook.best_bid_tick
            } else {
                orderbook.best_ask_tick
            };

            if best_tick == order.tick() {
                let (next_tick, has_liquidity) = self.books[order.book_key()]
                    .next_initialized_tick(order.tick(), order.is_bid())?;

                if order.is_bid() {
                    let new_best = if has_liquidity { next_tick } else { i16::MIN };
                    self.books[order.book_key()].best_bid_tick.write(new_best)?;
                } else {
                    let new_best = if has_liquidity { next_tick } else { i16::MAX };
                    self.books[order.book_key()].best_ask_tick.write(new_best)?;
                }
            }
        }

        if has_level_changed {
            self.books[order.book_key()]
                .tick_level_handler_mut(order.tick(), order.is_bid())
                .write(level)?;
        }

        // Refund tokens to maker - must match the escrow amount
        let orderbook = self.books[order.book_key()].read()?;
        if order.is_bid() {
            // Bid orders escrowed quote tokens using RoundingDirection::Up,
            // so refund must also use Up to return the exact escrowed amount
            let quote_amount =
                base_to_quote(order.remaining(), order.tick(), RoundingDirection::Up)
                    .ok_or(TempoPrecompileError::under_overflow())?;

            self.increment_balance(order.maker(), orderbook.quote, quote_amount)?;
        } else {
            // Ask orders are in base token, refund base amount (exact)
            self.increment_balance(order.maker(), orderbook.base, order.remaining())?;
        }

        // Clear the order from storage
        let credits = self.delete_order(&order)?;
        self.credit_dex_storage_slots(order.maker(), credits)?;

        // Emit OrderCancelled event
        self.emit_event(StablecoinDEXEvents::order_cancelled(order.order_id()))
    }

    /// Cancels an order whose maker is blocked by [`TIP403Registry`] policy, allowing anyone to
    /// clean up stale liquidity.
    ///
    /// [TIP-1015]: T4+ checks sender authorization on the escrow token and recipient
    /// authorization on the payout token. An order is stale if the maker fails either check.
    ///
    /// [TIP-1015]: <https://docs.tempo.xyz/protocol/tips/tip-1015>
    ///
    /// # Errors
    /// - `OrderDoesNotExist` — order ID not found or already fully filled
    /// - `OrderNotStale` — order maker is still authorized by TIP-403 policy
    pub fn cancel_stale_order(&mut self, order_id: u128) -> Result<()> {
        let order = self.orders[order_id].read()?;

        if order.maker().is_zero() {
            return Err(StablecoinDEXError::order_does_not_exist().into());
        }

        if self.is_maker_authorized(&order)? {
            Err(StablecoinDEXError::order_not_stale().into())
        } else {
            self.cancel_active_order(order)
        }
    }

    /// Returns `true` if the maker is authorized to keep the order open.
    ///
    /// Checks sender authorization on the escrow token (bid=quote, ask=base).
    /// T4+: also checks recipient authorization on the payout token (bid=base, ask=quote).
    fn is_maker_authorized(&self, order: &Order) -> Result<bool> {
        let book = self.books[order.book_key()].read()?;

        let (token_in, token_out) = if order.is_bid() {
            (book.quote, book.base)
        } else {
            (book.base, book.quote)
        };

        if !is_authorized_for_token(token_in, order.maker(), AuthRole::sender())? {
            return Ok(false);
        }

        if self.storage.spec().is_t4() {
            is_authorized_for_token(token_out, order.maker(), AuthRole::recipient())
        } else {
            Ok(true)
        }
    }

    /// Withdraws `amount` from the caller's DEX balance, transferring
    /// tokens back via [`TIP20Token`].
    ///
    /// # Errors
    /// - `InsufficientBalance` — DEX balance lower than withdrawal amount
    pub fn withdraw(&mut self, user: Address, token: Address, amount: u128) -> Result<()> {
        let current_balance = self.balance_of(user, token)?;
        if current_balance < amount {
            return Err(StablecoinDEXError::insufficient_balance().into());
        }
        self.sub_balance(user, token, amount)?;
        self.transfer(token, user, amount)?;

        Ok(())
    }

    /// Quotes the input required for exactly `amount_out` over a single book.
    ///
    /// On T12+ the quote walks the book order-by-order (via the same [`step_exact_out`]
    /// arithmetic the swap uses) so the quoted input equals what a swap would
    /// actually charge. The legacy per-tick quote rounds once per tick and can
    /// under-estimate the input across fragmented levels; it is kept for pre-T12
    /// historical determinism.
    fn quote_exact_out(&self, book_key: B256, amount_out: u128, is_bid: bool) -> Result<u128> {
        if self.storage.spec().is_t12() {
            self.quote_per_order(book_key, amount_out, is_bid, step_exact_out)
        } else {
            self.quote_exact_out_per_tick(book_key, amount_out, is_bid)
        }
    }

    /// Per-order quote that walks the book like swap execution but without
    /// mutating state, sharing the same `step` arithmetic so quoted amounts equal
    /// executed amounts.
    fn quote_per_order(
        &self,
        book_key: B256,
        amount: u128,
        is_bid: bool,
        step: impl Fn(u128, &Order, bool) -> Option<OrderStep>,
    ) -> Result<u128> {
        let level = self.get_best_price_level(book_key, is_bid)?;
        let order = self.orders[level.links.head].read_in_book(book_key)?;

        // Read-only walk: advance the cursor without settling, so the quote uses
        // the same per-order arithmetic and traversal as execution.
        walk_resting_orders(order, amount, is_bid, step, |order, fill| match fill {
            Fill::Partial(_) => Ok(None),
            Fill::Full => self.next_order_after(book_key, &order, is_bid),
        })
    }

    /// Legacy pre-T12 exact-output quote. It walks by tick-level aggregate
    /// liquidity and rounds once per tick, so it is intentionally unused after T12
    /// where quotes must match order-by-order execution.
    fn quote_exact_out_per_tick(
        &self,
        book_key: B256,
        amount_out: u128,
        is_bid: bool,
    ) -> Result<u128> {
        let mut remaining_out = amount_out;
        let mut amount_in = 0u128;
        let orderbook = self.books[book_key].read()?;

        let mut current_tick = if is_bid {
            orderbook.best_bid_tick
        } else {
            orderbook.best_ask_tick
        };
        // Check for no liquidity: i16::MIN means no bids, i16::MAX means no asks
        if current_tick == i16::MIN || current_tick == i16::MAX {
            return Err(StablecoinDEXError::insufficient_liquidity().into());
        }

        while remaining_out > 0 {
            let level = self.books[book_key]
                .tick_level_handler(current_tick, is_bid)
                .read()?;

            // If no liquidity at this level, move to next tick
            if level.total_liquidity == 0 {
                let (next_tick, initialized) =
                    self.books[book_key].next_initialized_tick(current_tick, is_bid)?;

                if !initialized {
                    return Err(StablecoinDEXError::insufficient_liquidity().into());
                }
                current_tick = next_tick;
                continue;
            }

            let (fill_amount, amount_in_tick) = if is_bid {
                // For bids: remaining_out is in quote, amount_in is in base
                // Round UP to ensure we collect enough base to cover exact output.
                // Note: this quote iterates per-tick, but execution iterates per-order.
                // If multiple orders exist at a tick, execution may charge slightly more
                // due to ceiling accumulation across order boundaries.
                let base_needed = quote_to_base(remaining_out, current_tick, RoundingDirection::Up)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                let fill_amount = if base_needed > level.total_liquidity {
                    level.total_liquidity
                } else {
                    base_needed
                };
                (fill_amount, fill_amount)
            } else {
                // For asks: remaining_out is in base, amount_in is in quote
                // Taker pays quote, maker receives quote - round UP to favor maker
                let fill_amount = if remaining_out > level.total_liquidity {
                    level.total_liquidity
                } else {
                    remaining_out
                };
                let quote_needed = base_to_quote(fill_amount, current_tick, RoundingDirection::Up)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                (fill_amount, quote_needed)
            };

            let amount_out_tick = if is_bid {
                // Round down amount_out_tick (user receives less quote).
                // Cap at remaining_out to avoid underflow from round-trip rounding:
                // when tick > 0, base_to_quote(quote_to_base(x, Up), Down) can exceed x by 1.
                base_to_quote(fill_amount, current_tick, RoundingDirection::Down)
                    .ok_or(TempoPrecompileError::under_overflow())?
                    .min(remaining_out)
            } else {
                fill_amount
            };

            remaining_out = remaining_out.saturating_sub(amount_out_tick);
            amount_in = amount_in
                .checked_add(amount_in_tick)
                .ok_or(TempoPrecompileError::under_overflow())?;

            // If we exhausted this level or filled our requirement, move to next tick
            if fill_amount == level.total_liquidity {
                let (next_tick, initialized) =
                    self.books[book_key].next_initialized_tick(current_tick, is_bid)?;

                if !initialized && remaining_out > 0 {
                    return Err(StablecoinDEXError::insufficient_liquidity().into());
                }
                current_tick = next_tick;
            } else {
                break;
            }
        }

        Ok(amount_in)
    }

    /// Find the trade path between two tokens
    /// Returns a vector of (book_key, base_for_quote) tuples for each hop
    /// Also validates that all pairs exist
    fn find_trade_path(&self, token_in: Address, token_out: Address) -> Result<Vec<(B256, bool)>> {
        // Cannot trade same token
        if token_in == token_out {
            return Err(StablecoinDEXError::identical_tokens().into());
        }

        // Validate that both tokens are TIP20 tokens
        if !token_in.is_tip20() || !token_out.is_tip20() {
            return Err(StablecoinDEXError::invalid_token().into());
        }

        // Check if direct or reverse pair exists
        let in_quote = TIP20Token::from_address(token_in)?.quote_token()?;
        let out_quote = TIP20Token::from_address(token_out)?.quote_token()?;

        if in_quote == token_out || out_quote == token_in {
            return self.validate_and_build_route(&[token_in, token_out]);
        }

        // Multi-hop: Find LCA and build path
        let path_in = self.find_path_to_root(token_in)?;
        let path_out = self.find_path_to_root(token_out)?;

        // Find the lowest common ancestor (LCA) using O(n+m) algorithm:
        // Build a HashSet from path_out for O(1) lookups, then iterate path_in
        let path_out_set: std::collections::HashSet<Address> = path_out.iter().copied().collect();
        let mut lca = None;
        for token_a in &path_in {
            if path_out_set.contains(token_a) {
                lca = Some(*token_a);
                break;
            }
        }

        let lca = lca.ok_or_else(StablecoinDEXError::pair_does_not_exist)?;

        // Build the trade path: token_in -> ... -> LCA -> ... -> token_out
        let mut trade_path = Vec::new();

        // Add path from token_in up to and including LCA
        for token in &path_in {
            trade_path.push(*token);
            if *token == lca {
                break;
            }
        }

        // Add path from LCA down to token_out (excluding LCA itself)
        let lca_to_out: Vec<Address> = path_out
            .iter()
            .take_while(|&&t| t != lca)
            .copied()
            .collect();

        // Reverse to get path from LCA to token_out
        trade_path.extend(lca_to_out.iter().rev());

        self.validate_and_build_route(&trade_path)
    }

    /// Validates that all pairs in the path exist and returns book keys with direction info.
    ///
    /// Multi-hop intermediate amounts are transitory: every route token is checked for pause state,
    /// but TIP-403 transfer policy is only enforced for the taker's initial input transfer and final
    /// output receipt, not for intermediate route tokens.
    ///
    /// # Errors
    /// - `InvalidToken` — a token address does not have a valid TIP-20 prefix
    /// - `PairDoesNotExist` — no orderbook exists for a hop in the route
    /// - `Paused` — a token in the route is paused (T3+)
    fn validate_and_build_route(&self, path: &[Address]) -> Result<Vec<(B256, bool)>> {
        let mut route = Vec::new();

        for [token_in, token_out] in path.array_windows::<2>().copied() {
            let (base, quote) = {
                let token_in_tip20 = TIP20Token::from_address(token_in)?;

                // Ensure that the token is not paused (spec: T3+)
                // Necessary because TIP20 transfer checks don't cover internal DEX balance updates
                if self.storage.spec().is_t3() {
                    token_in_tip20.check_not_paused()?;
                }

                if token_in_tip20.quote_token()? == token_out {
                    (token_in, token_out)
                } else {
                    let token_out_tip20 = TIP20Token::from_address(token_out)?;
                    if token_out_tip20.quote_token()? == token_in {
                        (token_out, token_in)
                    } else {
                        return Err(StablecoinDEXError::pair_does_not_exist().into());
                    }
                }
            };

            let book_key = compute_book_key(base, quote);
            let orderbook = self.books[book_key].read()?;

            if orderbook.base.is_zero() {
                return Err(StablecoinDEXError::pair_does_not_exist().into());
            }

            let is_base_for_quote = token_in == base;
            route.push((book_key, is_base_for_quote));
        }

        Ok(route)
    }

    /// Find the path from a token to the root (pathUSD)
    /// Returns a vector of addresses starting with the token and ending with pathUSD
    fn find_path_to_root(&self, mut token: Address) -> Result<Vec<Address>> {
        let mut path = vec![token];

        while token != PATH_USD_ADDRESS {
            token = TIP20Token::from_address(token)?.quote_token()?;
            path.push(token);
        }

        Ok(path)
    }

    /// Quotes the output for `amount_in` over a single book.
    ///
    /// On T12+ the quote walks the book order-by-order (via the same [`step_exact_in`]
    /// arithmetic the swap uses) so the quoted output equals what a swap would
    /// actually execute. The legacy per-tick quote aggregates `total_liquidity` and
    /// rounds once per tick, which over-estimates the output because summing
    /// per-order floors is `<=` the floor of the sum; it is kept for pre-T12
    /// historical determinism.
    fn quote_exact_in(&self, book_key: B256, amount_in: u128, is_bid: bool) -> Result<u128> {
        if self.storage.spec().is_t12() {
            self.quote_per_order(book_key, amount_in, is_bid, step_exact_in)
        } else {
            self.quote_exact_in_per_tick(book_key, amount_in, is_bid)
        }
    }

    /// Legacy pre-T12 exact-input quote. It walks by tick-level aggregate
    /// liquidity and rounds once per tick, so it is intentionally unused after T12
    /// where quotes must match order-by-order execution.
    fn quote_exact_in_per_tick(
        &self,
        book_key: B256,
        amount_in: u128,
        is_bid: bool,
    ) -> Result<u128> {
        let mut remaining_in = amount_in;
        let mut amount_out = 0u128;
        let orderbook = self.books[book_key].read()?;

        let mut current_tick = if is_bid {
            orderbook.best_bid_tick
        } else {
            orderbook.best_ask_tick
        };

        // Check for no liquidity: i16::MIN means no bids, i16::MAX means no asks
        if current_tick == i16::MIN || current_tick == i16::MAX {
            return Err(StablecoinDEXError::insufficient_liquidity().into());
        }

        while remaining_in > 0 {
            let level = self.books[book_key]
                .tick_level_handler(current_tick, is_bid)
                .read()?;

            // If no liquidity at this level, move to next tick
            if level.total_liquidity == 0 {
                let (next_tick, initialized) =
                    self.books[book_key].next_initialized_tick(current_tick, is_bid)?;

                if !initialized {
                    return Err(StablecoinDEXError::insufficient_liquidity().into());
                }
                current_tick = next_tick;
                continue;
            }

            // Compute (fill_amount, amount_out_tick, amount_consumed) based on hardfork
            let (fill_amount, amount_out_tick, amount_consumed) = if is_bid {
                // For bids: remaining_in is base, amount_out is quote
                let fill = remaining_in.min(level.total_liquidity);
                // Round down quote_out (user receives less quote)
                let quote_out = base_to_quote(fill, current_tick, RoundingDirection::Down)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                (fill, quote_out, fill)
            } else {
                // For asks: remaining_in is quote, amount_out is base
                // Taker pays quote, maker receives quote - round UP (zero-sum with maker)
                let base_to_get =
                    quote_to_base(remaining_in, current_tick, RoundingDirection::Down)
                        .ok_or(TempoPrecompileError::under_overflow())?;
                let fill = base_to_get.min(level.total_liquidity);
                let quote_consumed = base_to_quote(fill, current_tick, RoundingDirection::Up)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                (fill, fill, quote_consumed)
            };

            remaining_in = remaining_in
                .checked_sub(amount_consumed)
                .ok_or(TempoPrecompileError::under_overflow())?;
            amount_out = amount_out
                .checked_add(amount_out_tick)
                .ok_or(TempoPrecompileError::under_overflow())?;

            // If we exhausted this level, move to next tick
            if fill_amount == level.total_liquidity {
                let (next_tick, initialized) =
                    self.books[book_key].next_initialized_tick(current_tick, is_bid)?;

                if !initialized && remaining_in > 0 {
                    return Err(StablecoinDEXError::insufficient_liquidity().into());
                }
                current_tick = next_tick;
            } else {
                break;
            }
        }

        Ok(amount_out)
    }
}

/// Checks whether `address` is authorized under the transfer policy of `token` for the given
/// `role`. Returns `false` instead of erroring when the policy lookup fails.
fn is_authorized_for_token(token: Address, address: Address, role: AuthRole) -> Result<bool> {
    let policy_id = TIP20Token::from_address(token)?.transfer_policy_id()?;
    let registry = TIP403Registry::new();
    match registry.is_authorized_as(policy_id, address, role) {
        Ok(authorized) => Ok(authorized),
        Err(e) if is_policy_lookup_error(&e) => Ok(false),
        Err(e) => Err(e),
    }
}


