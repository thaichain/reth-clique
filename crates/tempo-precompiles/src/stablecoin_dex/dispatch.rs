//! ABI dispatch for the [`StablecoinDEX`] precompile.

use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IStablecoinDEX;

use crate::{
    Precompile, charge_input_cost, dispatch, mutate, preserve_storage_credits,
    stablecoin_dex::{
        StablecoinDEX, TickLevel,
        orderbook::{BookId, compute_book_key},
    },
    view,
};

impl Precompile for StablecoinDEX {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }
        dispatch!(
            calldata,
            |call| match call {
                IStablecoinDEX::IStablecoinDEXCalls {
                    place(call) => mutate(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.place(sender, c.token, c.amount, c.isBid, c.tick)
                    }),
                    placeFlip(call) => mutate(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.place_flip(sender, c.token, c.amount, c.isBid, c.tick, c.flipTick, false)
                    }),
                    balanceOf(call) => view(call, |c| self.balance_of(c.user, c.token)),
                    getOrder(call) => view(call, |c| {
                        self.get_order(c.orderId).map(|order| order.into())
                    }),
                    getTickLevel(call) => view(call, |c| {
                        let TickLevel { links, total_liquidity } = self.get_price_level(c.base, c.tick, c.isBid)?;
                        Ok((links.head, links.tail, total_liquidity).into())
                    }),
                    pairKey(call) => view(call, |c| Ok(compute_book_key(c.tokenA, c.tokenB))),
                    books(call) => view(call, |c| self.books(c.pairKey).map(Into::into)),
                    nextOrderId(call) => view(call, |_| self.next_order_id()),
                    createPair(call) => mutate(call, msg_sender, |_, c| {
                        preserve_storage_credits(self.address)?;
                        self.create_pair(c.base)
                    }),
                    withdraw(call) => mutate(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.withdraw(sender, c.token, c.amount)
                    }),
                    cancel(call) => mutate(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.cancel(sender, c.orderId)
                    }),
                    cancelStaleOrder(call) => mutate(call, msg_sender, |_, c| {
                        preserve_storage_credits(self.address)?;
                        self.cancel_stale_order(c.orderId)
                    }),
                    swapExactAmountIn(call) => mutate(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.swap_exact_amount_in(sender, c.tokenIn, c.tokenOut, c.amountIn, c.minAmountOut)
                    }),
                    swapExactAmountOut(call) => mutate(call, msg_sender, |sender, c| {
                        preserve_storage_credits(self.address)?;
                        self.swap_exact_amount_out(sender, c.tokenIn, c.tokenOut, c.amountOut, c.maxAmountIn)
                    }),
                    quoteSwapExactAmountIn(call) => view(call, |c| {
                        self.quote_swap_exact_amount_in(c.tokenIn, c.tokenOut, c.amountIn)
                    }),
                    quoteSwapExactAmountOut(call) => view(call, |c| {
                        self.quote_swap_exact_amount_out(c.tokenIn, c.tokenOut, c.amountOut)
                    }),
                    MIN_TICK(call) => view(call, |_| Ok(crate::stablecoin_dex::MIN_TICK)),
                    MAX_TICK(call) => view(call, |_| Ok(crate::stablecoin_dex::MAX_TICK)),
                    TICK_SPACING(call) => view(call, |_| Ok(crate::stablecoin_dex::TICK_SPACING)),
                    PRICE_SCALE(call) => view(call, |_| Ok(crate::stablecoin_dex::PRICE_SCALE)),
                    MIN_ORDER_AMOUNT(call) => view(call, |_| Ok(crate::stablecoin_dex::MIN_ORDER_AMOUNT)),
                    MIN_PRICE(call) => view(call, |_| Ok(self.min_price())),
                    MAX_PRICE(call) => view(call, |_| Ok(self.max_price())),
                    tickToPrice(call) => view(call, |c| self.tick_to_price(c.tick)),
                    priceToTick(call) => view(call, |c| self.price_to_tick(c.price)),

                    #[schedule(since = T7)]
                    storageCredits(call) => view(call, |c| self.storage_credits(c.user)),

                    #[schedule(since = T8)]
                    bookIndexForKey(call) => view(call, |c| {
                        let index = self.book_key_index(c.bookKey)?;
                        Ok((index.is_some(), index.unwrap_or(*BookId::UNSET)).into())
                    }),
                    #[schedule(since = T8)]
                    bookKeyForIndex(call) => view(call, |c| self.book_key_for_index(c.index)),
                    #[schedule(since = T8)]
                    setBookIndex(call) => mutate(call, msg_sender, |_, c| {
                        preserve_storage_credits(self.address)?;
                        self.set_book_index(c.index)
                    }),
                }
            }
        )
    }
}


