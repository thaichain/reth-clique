//! `StorableType`, `FromWord`, and `StorageKey` implementations for single-word primitives.
//!
//! Covers Rust integers, Alloy integers, Alloy fixed bytes, `bool`, and `Address`.

use alloy::primitives::{Address, U256};
use revm::interpreter::instructions::utility::{IntoAddress, IntoU256};
use tempo_precompiles_macros;

use crate::storage::types::*;

// rust integers: (u)int8, (u)int16, (u)int32, (u)int64, (u)int128
tempo_precompiles_macros::storable_rust_ints!();
// alloy integers: U8, I8, U16, I16, U32, I32, U64, I64, U128, I128, U256, I256
tempo_precompiles_macros::storable_alloy_ints!();
// alloy fixed bytes: FixedBytes<1>, FixedBytes<2>, ..., FixedBytes<32>
tempo_precompiles_macros::storable_alloy_bytes!();

// -- MANUAL STORAGE TRAIT IMPLEMENTATIONS -------------------------------------

impl StorableType for bool {
    const LAYOUT: Layout = Layout::Bytes(1);

    type Handler = Slot<Self>;

    fn handle(slot: U256, ctx: LayoutCtx, address: Address) -> Self::Handler {
        Slot::new_with_ctx(slot, ctx, address)
    }
}

impl super::sealed::OnlyPrimitives for bool {}
impl Packable for bool {}
impl FromWord for bool {
    #[inline]
    fn to_word(&self) -> U256 {
        if *self { U256::ONE } else { U256::ZERO }
    }

    #[inline]
    fn from_word(word: U256) -> crate::error::Result<Self> {
        Ok(!word.is_zero())
    }
}

impl StorageKey for bool {
    #[inline]
    fn as_storage_bytes(&self) -> impl AsRef<[u8]> {
        if *self { [1u8] } else { [0u8] }
    }
}

impl StorableType for Address {
    const LAYOUT: Layout = Layout::Bytes(20);
    type Handler = Slot<Self>;

    fn handle(slot: U256, ctx: LayoutCtx, address: Address) -> Self::Handler {
        Slot::new_with_ctx(slot, ctx, address)
    }
}

impl super::sealed::OnlyPrimitives for Address {}
impl Packable for Address {}
impl FromWord for Address {
    #[inline]
    fn to_word(&self) -> U256 {
        self.into_u256()
    }

    #[inline]
    fn from_word(word: U256) -> crate::error::Result<Self> {
        Ok(word.into_address())
    }
}

impl StorageKey for Address {
    #[inline]
    fn as_storage_bytes(&self) -> impl AsRef<[u8]> {
        self.as_slice()
    }
}


