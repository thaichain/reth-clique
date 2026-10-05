//! Dynamic array (`Vec<T>`) implementation for the storage traits.
//!
//! # Storage Layout
//!
//! Vec uses Solidity-compatible dynamic array storage:
//! - **Base slot**: Stores the array length (number of elements)
//! - **Data slots**: Start at `keccak256(len_slot)`, elements packed efficiently
//!
//! ## Multi-Slot Support
//!
//! - Supports both single-slot primitives and multi-slot types (structs, arrays)
//! - Element at index `i` starts at slot `data_start + i * T::SLOTS`

use alloy::primitives::{Address, U256};
use std::ops::{Index, IndexMut};

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{
        Handler, Layout, LayoutCtx, Storable, StorableType, StorageCtx, StorageOps,
        packing::{PackedSlot, calc_element_loc, calc_packed_slot_count},
        types::{HandlerCache, Slot},
    },
};

impl<T> StorableType for Vec<T>
where
    T: Storable,
{
    /// Vec base slot occupies one full storage slot (stores length).
    const LAYOUT: Layout = Layout::Slots(1);
    const IS_DYNAMIC: bool = true;
    type Handler = VecHandler<T>;

    fn handle(slot: U256, _ctx: LayoutCtx, address: Address) -> Self::Handler {
        VecHandler::new(slot, address)
    }
}

impl<T> Storable for Vec<T>
where
    T: Storable,
{
    fn load<S: StorageOps>(storage: &S, len_slot: U256, ctx: LayoutCtx) -> Result<Self> {
        debug_assert!(ctx.is_full(), "Dynamic arrays cannot be packed");

        // Read length from base slot
        let length = load_checked_len(storage, len_slot)?;

        if length == 0 {
            return Ok(Self::new());
        }

        // Pack elements if necessary. Vec elements can't be split across slots.
        let data_start = calc_data_slot(len_slot);
        if T::BYTES <= 16 {
            load_packed_elements(storage, data_start, length, T::BYTES)
        } else {
            load_unpacked_elements(storage, data_start, length)
        }
    }

    fn store<S: StorageOps>(&self, storage: &mut S, len_slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert!(ctx.is_full(), "Dynamic arrays cannot be packed");
        let data_start = calc_data_slot(len_slot);

        // (T5+) Cleanup stale tail, if necessary.
        if !ctx.skip_tail_cleanup() && StorageCtx.spec().is_t5() {
            let (prev_len, new_len) = (load_checked_len(storage, len_slot)?, self.len());
            if prev_len > new_len {
                clear_elements::<T, S>(storage, data_start, new_len, prev_len)?;
            }
        }

        // Write length to base slot.
        storage.store(len_slot, U256::from(self.len()))?;

        if self.is_empty() {
            return Ok(());
        }

        // Pack elements if necessary. Vec elements can't be split across slots.
        if T::BYTES <= 16 {
            store_packed_elements(self, storage, data_start)
        } else {
            store_unpacked_elements(self, storage, data_start)
        }
    }

    /// Custom delete for Vec: clears both length slot and all data slots.
    fn delete<S: StorageOps>(storage: &mut S, len_slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert!(ctx.is_full(), "Dynamic arrays cannot be packed");

        // Read length from base slot to determine how many slots to clear
        let length = load_checked_len(storage, len_slot)?;

        // Clear base slot (length)
        storage.store(len_slot, U256::ZERO)?;

        if length == 0 {
            return Ok(());
        }

        let data_start = calc_data_slot(len_slot);
        clear_elements::<T, S>(storage, data_start, 0, length)
    }
}

/// Type-safe handler for accessing `Vec<T>` in storage.
///
/// Provides both full-vector operations (read/write/delete) and individual element access.
/// The handler is a thin wrapper around a storage slot number and delegates full-vector
/// operations to `Slot<Vec<T>>`.
///
/// # Element Access
///
/// Use `at(index)` to get a `Slot<T>` for individual element operations with OOB guarantees.
/// Use `[index]` for its efficient counterpart without the check.
/// - For packed elements (T::BYTES ≤ 16): returns a packed `Slot<T>` with byte offsets
/// - For unpacked elements: returns a full `Slot<T>` for the element's dedicated slot
///
/// # Example
///
/// ```ignore
/// let handler = <Vec<u8> as StorableType>::handle(len_slot, LayoutCtx::FULL);
///
/// // Full vector operations
/// let vec = handler.read()?;
/// handler.write(vec![1, 2, 3])?;
///
/// // Individual element operations (at() returns Option, [] panics on OOB)
/// if let Some(slot) = handler.at(0) {
///     let elem = slot.read()?;
///     slot.write(42)?;
/// }
/// ```
///
/// # Capacity
///
/// Vectors have a maximum capacity of `u32::MAX / element_size` to prevent
/// arithmetic overflow in storage slot calculations.
#[derive(Debug, Clone)]
pub struct VecHandler<T: Storable> {
    len_slot: U256,
    address: Address,
    /// Keccak-derived data slot, computed on first use so handlers that never touch elements do
    /// not pay for the hash.
    data_slot: std::cell::OnceCell<U256>,
    cache: HandlerCache<usize, T::Handler>,
}

impl<T> Handler<Vec<T>> for VecHandler<T>
where
    T: Storable,
{
    /// Reads the entire vector from storage.
    #[inline]
    fn read(&self) -> Result<Vec<T>> {
        self.as_slot().read()
    }

    /// Writes the entire vector to storage.
    #[inline]
    fn write(&mut self, value: Vec<T>) -> Result<()> {
        self.as_slot().write(value)
    }

    /// Deletes the entire vector from storage (clears length and all elements).
    #[inline]
    fn delete(&mut self) -> Result<()> {
        self.as_slot().delete()
    }

    /// Reads the entire vector from transient storage.
    #[inline]
    fn t_read(&self) -> Result<Vec<T>> {
        self.as_slot().t_read()
    }

    /// Writes the entire vector to transient storage.
    #[inline]
    fn t_write(&mut self, value: Vec<T>) -> Result<()> {
        self.as_slot().t_write(value)
    }

    /// Deletes the entire vector from transient storage.
    #[inline]
    fn t_delete(&mut self) -> Result<()> {
        self.as_slot().t_delete()
    }
}

impl<T> VecHandler<T>
where
    T: Storable,
{
    /// Creates a new handler for the vector at the given base slot and address.
    #[inline]
    pub fn new(len_slot: U256, address: Address) -> Self {
        Self {
            len_slot,
            address,
            data_slot: std::cell::OnceCell::new(),
            cache: HandlerCache::new(),
        }
    }

    /// Maximum valid index for this element type, preventing arithmetic overflow
    /// in slot address computation (`index * T::SLOTS` or `index * T::BYTES`).
    const fn max_index() -> usize {
        if T::BYTES <= 16 {
            u32::MAX as usize / T::BYTES
        } else {
            u32::MAX as usize / T::SLOTS
        }
    }

    /// Returns the slot that stores the length of the dynamic array.
    #[inline]
    pub fn len_slot(&self) -> ::alloy::primitives::U256 {
        self.len_slot
    }

    /// Returns the base storage slot where this array's data is stored.
    ///
    /// Single-slot vectors pack all fields into this slot.
    /// Multi-slot vectors use consecutive slots starting from this base.
    #[inline]
    pub fn data_slot(&self) -> ::alloy::primitives::U256 {
        *self.data_slot.get_or_init(|| calc_data_slot(self.len_slot))
    }

    /// Returns a `Slot` accessor for full-vector operations.
    #[inline]
    fn as_slot(&self) -> Slot<Vec<T>> {
        Slot::new(self.len_slot, self.address)
    }

    /// Returns the length of the vector.
    #[inline]
    pub fn len(&self) -> Result<usize> {
        let slot = Slot::<U256>::new(self.len_slot, self.address);
        load_checked_len(&slot, self.len_slot)
    }

    /// Returns whether the vector is empty.
    #[inline]
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    #[inline]
    fn compute_handler(data_start: U256, address: Address, index: usize) -> T::Handler {
        // Pack small elements into shared slots, use T::SLOTS for multi-slot types
        let (slot, layout_ctx) = if T::BYTES <= 16 {
            let location = calc_element_loc(index, T::BYTES);
            (
                data_start + U256::from(location.offset_slots),
                LayoutCtx::packed(location.offset_bytes),
            )
        } else {
            (data_start + U256::from(index * T::SLOTS), LayoutCtx::FULL)
        };

        T::handle(slot, layout_ctx, address)
    }

    /// Returns a `Handler` for the element at the given index with bounds checking.
    ///
    /// The handler is computed on first access and cached for subsequent accesses.
    ///
    /// # Returns
    /// - If the SLOAD to read the length fails, returns an error.
    /// - If the index is OOB, returns `Ok(None)`.
    /// - Otherwise, returns `Ok(Some(&T::Handler))`.
    pub fn at(&self, index: usize) -> Result<Option<&T::Handler>> {
        if index >= self.len()? {
            return Ok(None);
        }

        let (data_start, address) = (self.data_slot(), self.address);
        Ok(Some(self.cache.get_or_insert(&index, || {
            Self::compute_handler(data_start, address, index)
        })))
    }

    /// Pushes a new element to the end of the vector.
    ///
    /// Automatically increments the length and handles packing for small types.
    ///
    /// Returns `Err` if the vector has reached its maximum capacity.
    #[inline]
    pub fn push(&mut self, value: T) -> Result<()>
    where
        T: Storable,
        T::Handler: Handler<T>,
    {
        // Read current length
        let length = self.len()?;
        if length >= Self::max_index() {
            return Err(TempoPrecompileError::Fatal("Vec is at max capacity".into()));
        }

        // Write element at the end. The tail slot is empty by construction.
        if T::BYTES <= 16 {
            let mut elem_slot = Self::compute_handler(self.data_slot(), self.address, length);
            elem_slot.write(value)?;
        } else {
            // Handlers always use `FULL` ctx. Since the slot we push to is guaranteed empty,
            // call `T::store` with `INIT` to skip tail-cleanup SLOADs for dynamic types.
            let elem_slot = self.data_slot() + U256::from(length * T::SLOTS);
            let mut storage = Slot::<T>::new(elem_slot, self.address);
            value.store(&mut storage, elem_slot, LayoutCtx::INIT)?;
        }

        // Increment length
        let mut length_slot = Slot::<U256>::new(self.len_slot, self.address);
        length_slot.write(U256::from(length + 1))
    }

    /// Pops the last element from the vector.
    ///
    /// Returns `None` if the vector is empty. Automatically decrements the length
    /// and zeros out the popped element's storage slot.
    #[inline]
    pub fn pop(&mut self) -> Result<Option<T>>
    where
        T: Storable,
        T::Handler: Handler<T>,
    {
        // Read current length
        let length = self.len()?;
        if length == 0 {
            return Ok(None);
        }
        let last_index = length - 1;

        // Read the last element
        let mut elem_slot = Self::compute_handler(self.data_slot(), self.address, last_index);
        let element = elem_slot.read()?;

        // Zero out the element's storage
        elem_slot.delete()?;

        // Decrement length
        let mut length_slot = Slot::<U256>::new(self.len_slot, self.address);
        length_slot.write(U256::from(last_index))?;

        Ok(Some(element))
    }
}

impl<T> Index<usize> for VecHandler<T>
where
    T: Storable,
{
    type Output = T::Handler;

    /// Returns a reference to the cached handler for the given index (unchecked).
    ///
    /// **WARNING:** Does not check bounds. Caller must ensure that the index is valid.
    /// For checked access use `.at(index)` instead.
    fn index(&self, index: usize) -> &Self::Output {
        let (data_start, address) = (self.data_slot(), self.address);
        self.cache
            .get_or_insert(&index, || Self::compute_handler(data_start, address, index))
    }
}

impl<T> IndexMut<usize> for VecHandler<T>
where
    T: Storable,
{
    /// Returns a mutable reference to the cached handler for the given index (unchecked).
    ///
    /// **WARNING:** Does not check bounds. Caller must ensure that the index is valid.
    /// For checked access use `.at(index)` instead.
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let (data_start, address) = (self.data_slot(), self.address);
        self.cache
            .get_or_insert_mut(&index, || Self::compute_handler(data_start, address, index))
    }
}

/// Loads a raw U256 from storage and interprets it as a length.
#[inline]
fn load_checked_len<S: StorageOps>(storage: &S, slot: U256) -> Result<usize> {
    let raw = storage.load(slot)?;
    if raw > U256::from(u32::MAX) {
        return Err(TempoPrecompileError::under_overflow());
    }
    Ok(raw.to::<usize>())
}

/// Calculate the starting slot for dynamic array data.
///
/// For Solidity compatibility, dynamic array data is stored at `keccak256(len_slot)`.
#[inline]
pub(crate) fn calc_data_slot(len_slot: U256) -> U256 {
    U256::from_be_bytes(alloy::primitives::keccak256(len_slot.to_be_bytes::<32>()).0)
}

/// Clears storage occupied exclusively by `Vec` elements in the index range `[from, to)`.
///
/// Packed elements (`T::BYTES <= 16`) share storage words, so this only zeroes whole packed
/// slots that contain no element before `from`:
///
/// - `from = 0` clears from slot 0. This is the delete path and clears every slot that may contain
///   any element in `[0, to)`; e.g. for 16-byte elements, `[0, 1)` clears slot 0.
/// - `from > 0` starts at `calc_packed_slot_count(from, T::BYTES)`, intentionally preserving the
///   boundary slot that may also contain live elements `< from`; e.g. for 16-byte elements,
///   `[1, 2)` clears nothing because elements 0 and 1 share slot 0. Shrink callers rely on the
///   subsequent packed-slot rewrite to clear stale lanes in that boundary slot.
///
/// Unpacked elements delegate to `T::delete` per element so nested dynamic storables are
/// recursively cleared.
fn clear_elements<T: Storable, S: StorageOps>(
    storage: &mut S,
    data_start: U256,
    from: usize,
    to: usize,
) -> Result<()> {
    if from >= to {
        return Ok(());
    }
    if T::BYTES <= 16 {
        // Vec elements can't be split across slots.
        let from_slots = calc_packed_slot_count(from, T::BYTES);
        let to_slots = calc_packed_slot_count(to, T::BYTES);
        for slot_idx in from_slots..to_slots {
            storage.store(data_start + U256::from(slot_idx), U256::ZERO)?;
        }
    } else {
        for elem_idx in from..to {
            let elem_slot = data_start + U256::from(elem_idx * T::SLOTS);
            T::delete(storage, elem_slot, LayoutCtx::FULL)?;
        }
    }
    Ok(())
}

/// Load packed elements from storage.
///
/// Used when `T::BYTES <= 16`, allowing multiple elements per slot.
fn load_packed_elements<T: Storable, S: StorageOps>(
    storage: &S,
    data_start: U256,
    length: usize,
    byte_count: usize,
) -> Result<Vec<T>> {
    debug_assert!(
        T::BYTES <= 16,
        "load_packed_elements requires T::BYTES <= 16"
    );
    let elements_per_slot = 32 / byte_count;
    let slot_count = calc_packed_slot_count(length, byte_count);

    let mut result = Vec::new();
    let mut current_offset = 0;

    for slot_idx in 0..slot_count {
        let slot_addr = data_start + U256::from(slot_idx);
        let slot_value = storage.load(slot_addr)?;
        let slot_packed = PackedSlot(slot_value);

        // How many elements in this slot?
        let elements_in_this_slot = if slot_idx == slot_count - 1 {
            // Last slot might be partially filled
            length - (slot_idx * elements_per_slot)
        } else {
            elements_per_slot
        };

        // Extract each element from this slot
        for _ in 0..elements_in_this_slot {
            let elem = T::load(&slot_packed, slot_addr, LayoutCtx::packed(current_offset))?;
            result.push(elem);

            // Move to next element position
            current_offset += byte_count;
            if current_offset >= 32 {
                current_offset = 0;
            }
        }

        // Reset offset for next slot
        current_offset = 0;
    }

    Ok(result)
}

/// Store packed elements to storage.
///
/// Packs multiple small elements into each 32-byte slot using bit manipulation.
fn store_packed_elements<T: Storable, S: StorageOps>(
    elements: &[T],
    storage: &mut S,
    data_start: U256,
) -> Result<()> {
    debug_assert!(
        T::BYTES <= 16,
        "store_packed_elements requires T::BYTES <= 16"
    );
    let elements_per_slot = 32 / T::BYTES;
    let slot_count = calc_packed_slot_count(elements.len(), T::BYTES);

    for slot_idx in 0..slot_count {
        let slot_addr = data_start + U256::from(slot_idx);
        let start_elem = slot_idx * elements_per_slot;
        let end_elem = (start_elem + elements_per_slot).min(elements.len());

        let slot_value = build_packed_slot(&elements[start_elem..end_elem], T::BYTES)?;
        storage.store(slot_addr, slot_value)?;
    }

    Ok(())
}

/// Build a packed storage slot from multiple elements.
///
/// Takes a slice of elements and packs them into a single U256 word.
fn build_packed_slot<T: Storable>(elements: &[T], byte_count: usize) -> Result<U256> {
    debug_assert!(T::BYTES <= 16, "build_packed_slot requires T::BYTES <= 16");
    let mut slot_value = PackedSlot(U256::ZERO);
    let mut current_offset = 0;

    for elem in elements {
        elem.store(
            &mut slot_value,
            U256::ZERO,
            LayoutCtx::packed(current_offset),
        )?;
        current_offset += byte_count;
    }

    Ok(slot_value.0)
}

/// Load unpacked elements from storage.
///
/// Used when elements don't pack efficiently (32 bytes or multi-slot types).
/// Each element occupies `T::SLOTS` consecutive slots.
fn load_unpacked_elements<T: Storable, S: StorageOps>(
    storage: &S,
    data_start: U256,
    length: usize,
) -> Result<Vec<T>> {
    let mut result = Vec::new();
    for index in 0..length {
        // Use T::SLOTS for proper multi-slot element addressing
        let elem_slot = data_start + U256::from(index * T::SLOTS);
        let elem = T::load(storage, elem_slot, LayoutCtx::FULL)?;
        result.push(elem);
    }
    Ok(result)
}

/// Store unpacked elements to storage.
///
/// Each element uses `T::SLOTS` consecutive slots.
fn store_unpacked_elements<T: Storable, S: StorageOps>(
    elements: &[T],
    storage: &mut S,
    data_start: U256,
) -> Result<()> {
    for (elem_idx, elem) in elements.iter().enumerate() {
        // Use T::SLOTS for proper multi-slot element addressing
        let elem_slot = data_start + U256::from(elem_idx * T::SLOTS);
        elem.store(storage, elem_slot, LayoutCtx::FULL)?;
    }

    Ok(())
}


