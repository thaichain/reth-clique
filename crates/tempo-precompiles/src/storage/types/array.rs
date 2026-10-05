//! Fixed-size array handler for the storage traits.
//!
//! # Storage Layout
//!
//! Fixed-size arrays `[T; N]` use Solidity-compatible array storage:
//! - **Base slot**: Arrays start directly at `base_slot` (not at keccak256)
//! - **Data slots**: Elements are stored sequentially, either packed or unpacked
//!
//! ## Packing Strategy
//!
//! - **Packed**: When `T::BYTES <= 16`, multiple elements fit in one slot
//! - **Unpacked**: When `T::BYTES > 16` or doesn't divide 32, each element uses full slot(s)

use alloy::primitives::{Address, U256};
use std::ops::{Index, IndexMut};
use tempo_precompiles_macros;

use crate::{
    error::Result,
    storage::{
        Handler, LayoutCtx, Storable, StorableType, packing,
        types::{HandlerCache, Slot},
    },
};

// fixed-size arrays: [T; N] for primitive types T and sizes 1-32
tempo_precompiles_macros::storable_arrays!();
// nested arrays: [[T; M]; N] for small primitive types
tempo_precompiles_macros::storable_nested_arrays!();

/// Type-safe handler for accessing fixed-size arrays `[T; N]` in storage.
///
/// Unlike `VecHandler`, arrays have a fixed compile-time size and store elements
/// directly at the base slot (not at `keccak256(base_slot)`).
///
/// # Element Access
///
/// Use `at(index)` to get a `Slot<T>` for individual element operations:
/// - For packed elements (T::BYTES ≤ 16): returns a packed `Slot<T>` with byte offsets
/// - For unpacked elements: returns a full `Slot<T>` for the element's dedicated slot
/// - Returns `None` if index is out of bounds
///
/// # Example
///
/// ```ignore
/// let handler = <[u8; 32] as StorableType>::handle(base_slot, LayoutCtx::FULL);
///
/// // Full array operations
/// let array = handler.read()?;
/// handler.write([1; 32])?;
///
/// // Individual element operations (at() returns Option, [] panics on OOB)
/// if let Some(slot) = handler.at(0) {
///     let elem = slot.read()?;
///     slot.write(42)?;
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ArrayHandler<T: StorableType, const N: usize> {
    base_slot: U256,
    address: Address,
    cache: HandlerCache<usize, T::Handler>,
}

impl<T: StorableType, const N: usize> ArrayHandler<T, N> {
    /// Creates a new handler for the array at the given base slot and address.
    #[inline]
    pub fn new(base_slot: U256, address: Address) -> Self {
        Self {
            base_slot,
            address,
            cache: HandlerCache::new(),
        }
    }

    /// Returns a `Slot` accessor for full-array operations.
    #[inline]
    fn as_slot(&self) -> Slot<[T; N]> {
        Slot::new(self.base_slot, self.address)
    }

    /// Returns the base storage slot where this array's data is stored.
    ///
    /// Single-slot arrays pack all fields into this slot.
    /// Multi-slot arrays use consecutive slots starting from this base.
    #[inline]
    pub fn base_slot(&self) -> ::alloy::primitives::U256 {
        self.base_slot
    }

    /// Returns the array size (known at compile time).
    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns whether the array is empty (always false for N > 0).
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Returns a `Handler` for the element at the given index.
    ///
    /// The returned handler automatically handles packing based on `T::BYTES`.
    /// The handler is computed on first access and cached for subsequent accesses.
    ///
    /// Returns `None` if the index is out of bounds (>= N).
    #[inline]
    pub fn at(&mut self, index: usize) -> Option<&T::Handler> {
        if index >= N {
            return None;
        }
        let (base_slot, address) = (self.base_slot, self.address);
        Some(
            self.cache
                .get_or_insert(&index, || Self::compute_handler(base_slot, address, index)),
        )
    }

    /// Computes the handler for a given index (unchecked).
    #[inline]
    fn compute_handler(base_slot: U256, address: Address, index: usize) -> T::Handler {
        // Pack small elements into shared slots, use T::SLOTS for multi-slot types
        let (slot, layout_ctx) = if T::BYTES <= 16 {
            let location = packing::calc_element_loc(index, T::BYTES);
            (
                base_slot + U256::from(location.offset_slots),
                LayoutCtx::packed(location.offset_bytes),
            )
        } else {
            (base_slot + U256::from(index * T::SLOTS), LayoutCtx::FULL)
        };

        T::handle(slot, layout_ctx, address)
    }
}

impl<T: StorableType, const N: usize> Index<usize> for ArrayHandler<T, N> {
    type Output = T::Handler;

    /// Returns a reference to the cached handler for the given index.
    ///
    /// **WARNING:** Panics if OOB. Caller must ensure that the index is valid.
    /// For gracefully checked access use `.at(index)` instead.
    fn index(&self, index: usize) -> &Self::Output {
        assert!(index < N, "index out of bounds: {index} >= {N}");
        let (base_slot, address) = (self.base_slot, self.address);
        self.cache
            .get_or_insert(&index, || Self::compute_handler(base_slot, address, index))
    }
}

impl<T: StorableType, const N: usize> IndexMut<usize> for ArrayHandler<T, N> {
    /// Returns a mutable reference to the cached handler for the given index.
    ///
    /// **WARNING:** Panics if OOB. Caller must ensure that the index is valid.
    /// For gracefully checked access use `.at(index)` instead.
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        assert!(index < N, "index out of bounds: {index} >= {N}");
        let (base_slot, address) = (self.base_slot, self.address);
        self.cache
            .get_or_insert_mut(&index, || Self::compute_handler(base_slot, address, index))
    }
}

impl<T: StorableType, const N: usize> Handler<[T; N]> for ArrayHandler<T, N>
where
    [T; N]: Storable,
{
    /// Reads the entire array from storage.
    #[inline]
    fn read(&self) -> Result<[T; N]> {
        self.as_slot().read()
    }

    /// Writes the entire array to storage.
    #[inline]
    fn write(&mut self, value: [T; N]) -> Result<()> {
        self.as_slot().write(value)
    }

    /// Deletes the entire array from storage (clears all elements).
    #[inline]
    fn delete(&mut self) -> Result<()> {
        self.as_slot().delete()
    }

    /// Reads the entire array from transient storage.
    #[inline]
    fn t_read(&self) -> Result<[T; N]> {
        self.as_slot().t_read()
    }

    /// Writes the entire array to transient storage.
    #[inline]
    fn t_write(&mut self, value: [T; N]) -> Result<()> {
        self.as_slot().t_write(value)
    }

    /// Deletes the entire array from transient storage (clears all elements).
    #[inline]
    fn t_delete(&mut self) -> Result<()> {
        self.as_slot().t_delete()
    }
}


