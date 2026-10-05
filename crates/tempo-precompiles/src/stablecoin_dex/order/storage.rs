//! Versioned storage for stablecoin DEX orders.
//!
//! The DEX business logic uses [`Order`] as its canonical order model. This module translates
//! between that logical type and the physical records stored onchain in the `orders` mapping.
//!
//! Two physical layouts are supported:
//!
//! - [`LegacyOrder`]: the original layout, identical to [`Order`]. Existing records may still be
//!   present in chain state and must remain readable.
//! - [`V1Order`]: the T8+ (TIP-1062) compact layout. It removes fields that can be derived from the
//!   mapping key and packs fields more tightly to reduce storage footprint.
//!
//! [`OrderHandler`] detects the record version on read, exposes field-level handlers for mutable
//! linked-list fields, and lazily migrates legacy records to V1 when they are rewritten.

use super::{__packing_legacy_order, LegacyOrder, ORDER_VERSION_V1, ORDER_VERSION_V2, Order};
use crate::{
    STABLECOIN_DEX_ADDRESS,
    error::{Result as StorageResult, TempoPrecompileError},
    stablecoin_dex::{self, StablecoinDEX, orderbook::BookId},
    storage::{
        Handler, HandlerCache, Layout, LayoutCtx, Slot, Storable, StorableType, StorageCtx,
        StorageKey, StorageOps, packing,
    },
};
use alloy::primitives::{Address, B256, FixedBytes, U256};
use std::ops::{Index, IndexMut};
use tempo_precompiles_macros::Storable;

/// Physical storage layout version for an order record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
#[repr(u8)]
pub(crate) enum OrderVersion {
    /// Original physical layout, identical to the canonical [`Order`] / [`LegacyOrder`] shape.
    Legacy,
    /// T8+ (TIP-1062): Optimized physical layout represented by [`V1Order`].
    V1,
    /// T8+ (TIP-1087): V1 prefix plus compact book index represented by [`V2Order`].
    V2,
}

impl TryFrom<U256> for OrderVersion {
    type Error = TempoPrecompileError;

    /// Decodes the packed version byte from order slot 0.
    fn try_from(slot0: U256) -> Result<Self, Self::Error> {
        let version = <u8 as Storable>::load(
            &packing::PackedSlot(slot0),
            U256::ZERO,
            LayoutCtx::packed(__packing_v1_order::VERSION_LOC.offset_bytes),
        )?;

        match version {
            0 => Ok(Self::Legacy),
            ORDER_VERSION_V1 => Ok(Self::V1),
            ORDER_VERSION_V2 => Ok(Self::V2),
            version => Err(TempoPrecompileError::Fatal(format!(
                "unknown stablecoin DEX order storage version {version}"
            ))),
        }
    }
}

struct OrderFlags;

impl OrderFlags {
    const IS_BID: u8 = 1 << 0;
    const IS_FLIP: u8 = 1 << 1;

    /// Packs logical order flags into a metadata byte.
    #[inline]
    fn pack(is_bid: bool, is_flip: bool) -> u8 {
        (u8::from(is_bid) * Self::IS_BID) | (u8::from(is_flip) * Self::IS_FLIP)
    }

    /// Returns whether the metadata marks the order as a bid (`true`) or ask (`false`).
    #[inline]
    fn is_bid(metadata: u8) -> bool {
        metadata & Self::IS_BID != 0
    }

    /// Returns whether the metadata marks the order as a flip order.
    #[inline]
    fn is_flip(metadata: u8) -> bool {
        metadata & Self::IS_FLIP != 0
    }
}

/// Compact TIP-1062 physical order layout.
///
/// V1 omits `order_id` by synthesizing it from the `orders` mapping key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
struct V1Order {
    /// Address of the user who placed the order.
    maker: Address,
    /// Packed order metadata. Bit 0 stores `is_bid`; bit 1 stores `is_flip`.
    metadata: u8,
    /// Price tick for the order's current side.
    tick: i16,
    /// Destination tick for a fully filled flip order.
    flip_tick: i16,
    /// Reserved bytes in packed slot 0. Kept zeroed for deterministic encoding and future use.
    _unused: FixedBytes<6>,
    /// Physical layout marker stored in packed slot 0.
    version: OrderVersion,
    /// Original order amount.
    amount: u128,
    /// Remaining unfilled amount.
    remaining: u128,
    /// Previous order ID in the tick-level FIFO linked list.
    prev: u128,
    /// Next order ID in the tick-level FIFO linked list.
    next: u128,
    /// Orderbook key identifying the trading pair.
    book_key: B256,
}

impl V1Order {
    /// Converts the logical order into the compact V1 physical layout.
    fn new(order: Order) -> Self {
        Self {
            maker: order.maker,
            tick: order.tick,
            metadata: OrderFlags::pack(order.is_bid, order.is_flip),
            flip_tick: order.flip_tick,
            _unused: FixedBytes::<6>::ZERO,
            version: OrderVersion::V1,
            book_key: order.book_key,
            amount: order.amount,
            remaining: order.remaining,
            prev: order.prev,
            next: order.next,
        }
    }

    /// Converts V1 storage back into the logical order, restoring `order_id` from the mapping key.
    fn into_order(self, order_id: u128) -> Order {
        Order {
            order_id,
            maker: self.maker,
            book_key: self.book_key,
            is_bid: OrderFlags::is_bid(self.metadata),
            tick: self.tick,
            amount: self.amount,
            remaining: self.remaining,
            prev: self.prev,
            next: self.next,
            is_flip: OrderFlags::is_flip(self.metadata),
            flip_tick: self.flip_tick,
        }
    }
}

/// Compact TIP-1087 physical order layout.
///
/// V2 replaces V1's repeated `book_key` slot with a compact index into the DEX `book_keys` vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
struct V2Order {
    /// Address of the user who placed the order.
    maker: Address,
    /// Packed order metadata. Bit 0 stores `is_bid`; bit 1 stores `is_flip`.
    metadata: u8,
    /// Price tick for the order's current side.
    tick: i16,
    /// Destination tick for a fully filled flip order.
    flip_tick: i16,
    /// Index into the DEX `book_keys` vector.
    book_index: u32,
    /// Reserved bytes in packed slot 0.
    _unused: FixedBytes<2>,
    /// Physical layout marker stored in packed slot 0.
    version: OrderVersion,
    /// Original order amount.
    amount: u128,
    /// Remaining unfilled amount.
    remaining: u128,
    /// Previous order ID in the tick-level FIFO linked list.
    prev: u128,
    /// Next order ID in the tick-level FIFO linked list.
    next: u128,
}

impl V2Order {
    /// Converts the logical order into the compact V2 physical layout.
    fn new(order: Order, book_index: u32) -> Self {
        Self {
            maker: order.maker,
            metadata: OrderFlags::pack(order.is_bid, order.is_flip),
            tick: order.tick,
            flip_tick: order.flip_tick,
            book_index,
            _unused: FixedBytes::<2>::ZERO,
            version: OrderVersion::V2,
            amount: order.amount,
            remaining: order.remaining,
            prev: order.prev,
            next: order.next,
        }
    }

    /// Converts V2 storage back into the logical order, restoring `order_id` and `book_key`.
    fn into_order(self, order_id: u128, book_key: B256) -> Order {
        Order {
            order_id,
            maker: self.maker,
            book_key,
            is_bid: OrderFlags::is_bid(self.metadata),
            tick: self.tick,
            amount: self.amount,
            remaining: self.remaining,
            prev: self.prev,
            next: self.next,
            is_flip: OrderFlags::is_flip(self.metadata),
            flip_tick: self.flip_tick,
        }
    }
}

/// Version-aware storage handler for a single DEX order.
#[derive(Debug, Clone)]
pub(crate) struct OrderHandler {
    /// Base storage slot for this order's mapping value.
    base_slot: U256,
    /// Mapping key for this order. V1 storage omits `order_id`, so reads restore it from here.
    order_id: u128,
    /// Contract address whose storage contains the order mapping.
    address: Address,
}

impl OrderHandler {
    #[inline]
    fn new(base_slot: U256, order_id: u128, address: Address) -> Self {
        Self {
            base_slot,
            order_id,
            address,
        }
    }

    /// Returns the order's maker address.
    pub(crate) fn maker(&self) -> StorageResult<Address> {
        let (version, slot0) = self.version_and_slot()?;
        let loc = match version {
            OrderVersion::Legacy => __packing_legacy_order::MAKER_LOC,
            OrderVersion::V1 | OrderVersion::V2 => __packing_v1_order::MAKER_LOC,
        };

        // T8+ version detection loads slot 0. We reuse it when the maker is stored there.
        if let Some(slot0) = slot0
            && loc.offset_slots == 0
        {
            Address::load(
                &packing::PackedSlot(slot0),
                U256::ZERO,
                LayoutCtx::packed(loc.offset_bytes),
            )
        } else {
            Slot::new_at_loc(self.base_slot, loc, self.address).read()
        }
    }

    /// Returns a storage handler for the order's remaining amount.
    pub(crate) fn remaining(&self) -> StorageResult<Slot<u128>> {
        self.u128_field(
            __packing_legacy_order::REMAINING_LOC,
            __packing_v1_order::REMAINING_LOC,
        )
    }

    /// Returns a storage handler for the previous linked-list pointer.
    pub(crate) fn prev(&self) -> StorageResult<Slot<u128>> {
        self.u128_field(
            __packing_legacy_order::PREV_LOC,
            __packing_v1_order::PREV_LOC,
        )
    }

    /// Returns a storage handler for the next linked-list pointer.
    pub(crate) fn next(&self) -> StorageResult<Slot<u128>> {
        self.u128_field(
            __packing_legacy_order::NEXT_LOC,
            __packing_v1_order::NEXT_LOC,
        )
    }

    /// Selects the version-specific location for a mutable `u128` field.
    fn u128_field(
        &self,
        legacy: packing::FieldLocation,
        compact: packing::FieldLocation,
    ) -> StorageResult<Slot<u128>> {
        let loc = match self.version()? {
            OrderVersion::Legacy => legacy,
            OrderVersion::V1 | OrderVersion::V2 => compact,
        };

        Ok(Slot::new_at_loc(self.base_slot, loc, self.address))
    }

    /// Returns the physical storage version and the loaded base slot, when read.
    pub(crate) fn version_and_slot(&self) -> StorageResult<(OrderVersion, Option<U256>)> {
        if !StorageCtx.spec().is_t8() {
            return Ok((OrderVersion::Legacy, None));
        }

        let slot0 = self.load(self.base_slot)?;
        Ok((OrderVersion::try_from(slot0)?, Some(slot0)))
    }

    /// Returns the physical storage version.
    pub(crate) fn version(&self) -> StorageResult<OrderVersion> {
        self.version_and_slot().map(|(version, _)| version)
    }

    /// Reads this order using a known owning book key, skipping V2 index resolution.
    pub(crate) fn read_in_book(&self, book_key: B256) -> StorageResult<Order> {
        self.read_with_book_key(Some(book_key))
    }

    /// Reads this order, skipping V2 index resolution when a book key is provided.
    fn read_with_book_key(&self, known_book: Option<B256>) -> StorageResult<Order> {
        match self.version()? {
            OrderVersion::Legacy => LegacyOrder::load(self, self.base_slot, LayoutCtx::FULL),
            OrderVersion::V1 => V1Order::load(self, self.base_slot, LayoutCtx::FULL)
                .map(|res| res.into_order(self.order_id)),
            OrderVersion::V2 => {
                let order = V2Order::load(self, self.base_slot, LayoutCtx::FULL)?;
                let book_key = match known_book {
                    None => StablecoinDEX::new().book_key_for_index(order.book_index)?,
                    Some(book_key) => book_key,
                };
                Ok(order.into_order(self.order_id, book_key))
            }
        }
    }

    /// Writes this order using a known owning book ID, skipping index resolution.
    pub(crate) fn write_in_book(&mut self, value: Order, book_id: BookId) -> StorageResult<()> {
        self.write_with_book_id(value, Some(book_id))
    }

    /// Writes this order, skipping V2 index resolution when a book ID is provided.
    fn write_with_book_id(&mut self, value: Order, known_id: Option<BookId>) -> StorageResult<()> {
        debug_assert_eq!(value.order_id, self.order_id);

        if !StorageCtx.spec().is_t8() {
            return value.store(self, self.base_slot, LayoutCtx::FULL);
        }

        let (old_version, slot0) = self.version_and_slot()?;
        let old_slots = match old_version {
            OrderVersion::Legacy => LegacyOrder::SLOTS,
            OrderVersion::V1 => V1Order::SLOTS,
            OrderVersion::V2 => V2Order::SLOTS,
        };

        // If known, use the book ID. Otherwise resolve it from storage.
        let book_index = match known_id {
            None => StablecoinDEX::new().book_key_index(value.book_key)?,
            Some(id) => id.index(),
        };

        let new_slots = if let Some(book_index) = book_index {
            V2Order::new(value, book_index).store(self, self.base_slot, LayoutCtx::FULL)?;
            V2Order::SLOTS
        } else {
            V1Order::new(value).store(self, self.base_slot, LayoutCtx::FULL)?;
            V1Order::SLOTS
        };

        if slot0.is_none_or(|val| !val.is_zero()) {
            for offset in new_slots..old_slots {
                self.store(self.base_slot.wrapping_add(U256::from(offset)), U256::ZERO)?;
            }
        }
        Ok(())
    }
}

impl StorageOps for OrderHandler {
    fn store(&mut self, slot: U256, value: U256) -> StorageResult<()> {
        StorageCtx.sstore(self.address, slot, value)
    }

    fn load(&self, slot: U256) -> StorageResult<U256> {
        StorageCtx.sload(self.address, slot)
    }
}

impl Handler<Order> for OrderHandler {
    /// Reads the order using the cached or detected physical layout version.
    fn read(&self) -> StorageResult<Order> {
        self.read_with_book_key(None)
    }

    /// Writes the order, migrating T8 records to V1/V2.
    fn write(&mut self, value: Order) -> StorageResult<()> {
        self.write_with_book_id(value, None)
    }

    /// Deletes the physical slots for the cached or detected order layout.
    fn delete(&mut self) -> StorageResult<()> {
        let slot_count = match self.version()? {
            OrderVersion::Legacy => LegacyOrder::SLOTS,
            OrderVersion::V1 => V1Order::SLOTS,
            OrderVersion::V2 => V2Order::SLOTS,
        };

        for offset in 0..slot_count {
            self.store(self.base_slot.wrapping_add(U256::from(offset)), U256::ZERO)?;
        }

        Ok(())
    }

    fn t_read(&self) -> StorageResult<Order> {
        Err(TempoPrecompileError::Fatal(
            "transient order storage is unsupported".to_string(),
        ))
    }

    fn t_write(&mut self, _value: Order) -> StorageResult<()> {
        Err(TempoPrecompileError::Fatal(
            "transient order storage is unsupported".to_string(),
        ))
    }

    fn t_delete(&mut self) -> StorageResult<()> {
        Err(TempoPrecompileError::Fatal(
            "transient order storage is unsupported".to_string(),
        ))
    }
}

/// Specialized `Mapping<u128, Order>` wrapper for stablecoin DEX `orders`.
///
/// Unlike generic storage mappings, this wrapper is tied to the stablecoin DEX storage layout and
/// address. Handlers retain the `order_id` key because V1 order values no longer store it, so reads
/// synthesize it from this key.
#[derive(Debug)]
pub(crate) struct OrderMapping {
    /// Per-order handler cache keyed by order ID.
    cache: HandlerCache<u128, OrderHandler>,
}

impl OrderMapping {
    #[inline]
    fn new() -> Self {
        Self {
            cache: HandlerCache::new(),
        }
    }

    #[inline]
    fn base_slot() -> U256 {
        stablecoin_dex::slots::ORDERS
    }

    /// Returns a cached handler for `order_id`.
    pub(crate) fn at(&self, order_id: u128) -> &OrderHandler {
        self.cache.get_or_insert(&order_id, || {
            OrderHandler::new(
                order_id.mapping_slot(Self::base_slot()),
                order_id,
                STABLECOIN_DEX_ADDRESS,
            )
        })
    }

    /// Returns a mutable cached handler for `order_id`.
    pub(crate) fn at_mut(&mut self, order_id: u128) -> &mut OrderHandler {
        self.cache.get_or_insert_mut(&order_id, || {
            OrderHandler::new(
                order_id.mapping_slot(Self::base_slot()),
                order_id,
                STABLECOIN_DEX_ADDRESS,
            )
        })
    }
}

impl Index<u128> for OrderMapping {
    type Output = OrderHandler;

    /// Returns a cached order handler by order ID.
    fn index(&self, order_id: u128) -> &Self::Output {
        self.at(order_id)
    }
}

impl IndexMut<u128> for OrderMapping {
    /// Returns a mutable cached order handler by order ID.
    fn index_mut(&mut self, order_id: u128) -> &mut Self::Output {
        self.at_mut(order_id)
    }
}

impl Clone for OrderMapping {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl Default for OrderMapping {
    fn default() -> Self {
        Self::new()
    }
}

impl StorableType for OrderMapping {
    const LAYOUT: Layout = Layout::Slots(1);

    type Handler = Self;

    fn handle(_slot: U256, _ctx: LayoutCtx, _address: Address) -> Self::Handler {
        Self::new()
    }
}


