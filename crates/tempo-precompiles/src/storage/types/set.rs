//! OpenZeppelin's EnumerableSet implementation for EVM storage using Rust primitives.
//! <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/structs/EnumerableSet.sol>
//!
//! # Storage Layout
//!
//! EnumerableSet uses two storage structures:
//! - **Values Vec**: A `Vec<T>` storing all set elements at `keccak256(base_slot)`
//! - **Positions Mapping**: A `Mapping<T, u32>` at `base_slot + 1` storing 1-indexed positions
//!   - Position 0 means the value is not in the set
//!   - Position N means the value is at index N-1 in the values array
//!
//! # Design
//!
//! Two complementary types:
//! - `Set<T>`: Read-only in-memory snapshot. `Vec<T>` wrapper. Ordered like storage.
//! - `SetHandler<T>`: Storage operations.
//!
//! # Usage Patterns
//!
//! ## Single Operations (O(1) each)
//! ```ignore
//! handler.insert(addr)?;   // Direct storage write
//! handler.remove(&addr)?;  // Direct storage write
//! handler.contains(&addr)?; // Direct storage read
//! ```
//!
//! ## Bulk Read
//! ```ignore
//! let set: Set<Address> = handler.read()?;
//! for addr in &set {
//!     // Iteration preserves storage order
//!     // set[i] == handler.at(i)
//! }
//! ```
//!
//! ## Bulk Mutation
//! ```ignore
//! let mut vec: Vec<_> = handler.read()?.into();
//! vec.push(new_addr);
//! vec.retain(|a| a != &old_addr);
//! handler.write(vec.into())?;  // `Set::from(vec)` deduplicates
//! ```

use alloy::primitives::{Address, U256};
use std::{
    collections::HashSet,
    fmt,
    hash::Hash,
    ops::{Deref, Index},
};

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{
        Handler, Layout, LayoutCtx, Storable, StorableType, StorageKey, StorageOps,
        types::{Mapping, Slot, vec::VecHandler},
    },
};

/// Read-only snapshot of a set stored via [`SetHandler`].
///
/// Elements are ordered by their position in the underlying storage array.
/// This order is **not** guaranteed to match insertion order: `SetHandler::remove`
/// uses swap-and-pop semantics, so removing a non-tail element moves the last
/// element into the vacated slot.
///
/// To mutate:
/// 1. Convert to `Vec<T>` with `.into()`
/// 2. Modify the Vec
/// 3. Convert back with `Set::from(vec)` (deduplicates, preserves first-occurrence order)
/// 4. Write with `handler.write(set)`
///
/// For single-element mutations, use `SetHandler` methods directly.
///
/// Implements `Deref<Target = [T]>`, so all slice methods are available:
/// `len()`, `is_empty()`, `iter()`, `get()`, `contains()`, indexing, etc.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Set<T>(Vec<T>);

impl<T> Set<T> {
    /// Creates a new empty set.
    #[inline]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Creates a set from a vector that is already known to contain no duplicates.
    ///
    /// # IMPORTANT
    ///
    /// The caller **must** guarantee that `vec` contains no duplicate elements.
    /// Violating this breaks the position-mapping invariant in storage: two equal values would
    /// share a single position slot, causing silent data corruption on subsequent `remove()` calls.
    #[inline]
    pub fn new_unchecked(vec: Vec<T>) -> Self {
        Self(vec)
    }
}

impl<T> Deref for Set<T> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<T> From<Set<T>> for Vec<T> {
    #[inline]
    fn from(set: Set<T>) -> Self {
        set.0
    }
}

impl<T: Eq + Hash + Clone> From<Vec<T>> for Set<T> {
    /// Creates a set from a vector, removing duplicates.
    ///
    /// Preserves the order of first occurrences.
    fn from(vec: Vec<T>) -> Self {
        let (mut seen, mut deduped) = (HashSet::new(), Vec::new());
        for item in vec {
            if seen.insert(item.clone()) {
                deduped.push(item);
            }
        }
        Self(deduped)
    }
}

impl<T: Eq + Hash + Clone> FromIterator<T> for Set<T> {
    /// Creates a set from an iterator, removing duplicates.
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let vec: Vec<T> = iter.into_iter().collect();
        Self::from(vec)
    }
}

impl<T> IntoIterator for Set<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Set<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Type-safe handler for accessing `Set<T>` in storage.
///
/// Provides the OZ storage operations but following the naming convention of `HashSet`:
///
/// | Method         | OZ equivalent    |
/// |----------------|------------------|
/// | `insert()`     | `add()`          |
/// | `remove()`     | `remove()`       |
/// | `contains()`   | `contains()`     |
/// | `len()`        | `length()`       |
/// | `at()`         | `at()`           |
/// | `read()`       | `values()`       |
/// | `read_range()` | `values_range()` |
///
/// Also implements `Handler<Set<T>>` for bulk operations:
/// - `read`: Load all elements as `Set<T>`
/// - `write`: Replace entire set
/// - `delete`: Remove all elements
pub struct SetHandler<T>
where
    T: Storable + StorageKey + Hash + Eq + Clone,
{
    /// Handler for the values vector (stores actual elements).
    values: VecHandler<T>,
    /// Handler for the positions mapping (value -> 1-indexed position).
    positions: Mapping<T, u32>,
    /// The base slot for the set.
    base_slot: U256,
    /// Contract address.
    address: Address,
}

/// Set occupies 2 slots:
///
/// - Slot 0: `Vec` length slot, with data at `keccak256(slot)`
/// - Slot 1: `Mapping` base slot for positions
impl<T> StorableType for Set<T>
where
    T: Storable + StorageKey + Hash + Eq + Clone,
{
    const LAYOUT: Layout = Layout::Slots(2);
    const IS_DYNAMIC: bool = true;
    type Handler = SetHandler<T>;

    fn handle(slot: U256, _ctx: LayoutCtx, address: Address) -> Self::Handler {
        SetHandler::new(slot, address)
    }
}

/// Storable implementation for `Set<T>`.
impl<T> Storable for Set<T>
where
    T: Storable + StorageKey + Hash + Eq + Clone,
    T::Handler: Handler<T>,
{
    fn load<S: StorageOps>(storage: &S, slot: U256, _ctx: LayoutCtx) -> Result<Self> {
        let values: Vec<T> = Vec::load(storage, slot, LayoutCtx::FULL)?;
        Ok(Self(values))
    }

    fn store<S: StorageOps>(&self, _storage: &mut S, _slot: U256, _ctx: LayoutCtx) -> Result<()> {
        Err(TempoPrecompileError::Fatal(
            "Set must be stored via SetHandler::write() to maintain position invariants".into(),
        ))
    }

    fn delete<S: StorageOps>(storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()> {
        let values: Vec<T> = Vec::load(storage, slot, LayoutCtx::FULL)?;

        for value in values {
            let pos_slot = value.mapping_slot(slot + U256::ONE);
            <U256 as Storable>::delete(storage, pos_slot, LayoutCtx::FULL)?;
        }

        <Vec<T> as Storable>::delete(storage, slot, ctx)
    }
}

/// Converts a 0-based index to a 1-based position for storage.
///
/// Returns an error if the result would overflow `u32`, which would corrupt the
/// sentinel value (`0` means "not present") used by `contains()` and `remove()`.
#[inline]
fn checked_position(index: usize) -> Result<u32> {
    u32::try_from(index)
        .ok()
        .and_then(|i| i.checked_add(1))
        .ok_or_else(TempoPrecompileError::under_overflow)
}

impl<T> SetHandler<T>
where
    T: Storable + StorageKey + Hash + Eq + Clone,
{
    /// Creates a new handler for the set at the given base slot.
    ///
    /// - `base_slot`: Used as the Vec's length slot
    /// - `base_slot + 1`: Used as the Mapping's base slot
    pub fn new(base_slot: U256, address: Address) -> Self {
        Self {
            values: VecHandler::new(base_slot, address),
            positions: Mapping::new(base_slot + U256::ONE, address),
            base_slot,
            address,
        }
    }

    /// Returns the base storage slot for this set.
    #[inline]
    pub fn base_slot(&self) -> U256 {
        self.base_slot
    }

    /// Returns the number of elements in the set.
    #[inline]
    pub fn len(&self) -> Result<usize> {
        self.values.len()
    }

    /// Returns whether the set is empty.
    #[inline]
    pub fn is_empty(&self) -> Result<bool> {
        self.values.is_empty()
    }

    /// Returns true if the value is in the set.
    pub fn contains(&self, value: &T) -> Result<bool>
    where
        T: StorageKey + Hash + Eq + Clone,
    {
        self.positions.at(value).read().map(|pos| pos != 0)
    }

    /// Inserts a value into the set.
    ///
    /// Returns `true` if the value was inserted (not already present).
    /// Returns `false` if the value was already in the set.
    #[inline]
    pub fn insert(&mut self, value: T) -> Result<bool>
    where
        T: StorageKey + Hash + Eq + Clone,
        T::Handler: Handler<T>,
    {
        // Check if already present
        if self.contains(&value)? {
            return Ok(false);
        }

        // Store position (1-indexed: position N means index N-1)
        let length = self.values.len()?;
        self.positions
            .at_mut(&value)
            .write(checked_position(length)?)?;

        // Push value to the array
        self.values.push(value)?;

        Ok(true)
    }

    /// Removes a value from the set.
    ///
    /// Returns `true` if the value was removed. Otherwise, returns `false`.
    #[inline]
    pub fn remove(&mut self, value: &T) -> Result<bool>
    where
        T: StorageKey + Hash + Eq + Clone,
        T::Handler: Handler<T>,
    {
        // Get position (1-indexed, 0 means not present)
        let position = self.positions.at(value).read()?;
        if position == 0 {
            return Ok(false);
        }

        let len = self.values.len()?;
        // Validate invariants
        debug_assert!(
            len != 0 && (position as usize) <= len,
            "Set invariant violation: position exceeds length"
        );

        // Convert to 0-indexed
        let last_index = len - 1;
        let index = (position - 1) as usize;

        // Swap with last element if not already last
        if index != last_index {
            let last_value = self.values[last_index].read()?;
            self.positions.at_mut(&last_value).write(position)?;
            self.values[index].write(last_value)?;
        }

        // Delete the last element and decrement its length.
        // Equivalent to `self.values.pop()`, but without the OOB checks.
        self.values[last_index].delete()?;
        Slot::<U256>::new(self.values.len_slot(), self.address).write(U256::from(last_index))?;

        // Clear removed value's position
        self.positions.at_mut(value).delete()?;

        Ok(true)
    }

    /// Returns the value at the given index with bounds checking.
    ///
    /// # Returns
    /// - If the SLOAD to read the length fails, returns an error.
    /// - If the index is OOB, returns `Ok(None)`.
    /// - Otherwise, returns `Ok(Some(T))`.
    pub fn at(&self, index: usize) -> Result<Option<T>>
    where
        T::Handler: Handler<T>,
    {
        if index >= self.len()? {
            return Ok(None);
        }
        Ok(Some(self.values[index].read()?))
    }

    /// Reads a range of values from the set.
    ///
    /// This is a partial version of `read()` for when you only need a subset.
    pub fn read_range(&self, start: usize, end: usize) -> Result<Vec<T>>
    where
        T::Handler: Handler<T>,
    {
        let len = self.len()?;
        let end = end.min(len);
        let start = start.min(end);

        let mut result = Vec::new();
        for i in start..end {
            result.push(self.values[i].read()?);
        }
        Ok(result)
    }
}

impl<T> Handler<Set<T>> for SetHandler<T>
where
    T: Storable + StorageKey + Hash + Eq + Clone,
    T::Handler: Handler<T>,
{
    /// Reads all elements from storage as a `Set<T>`.
    ///
    /// The returned `Set` preserves storage order: `set[i] == handler.at(i)`.
    fn read(&self) -> Result<Set<T>> {
        let len = self.len()?;
        let mut vec = Vec::new();

        for i in 0..len {
            vec.push(self.values[i].read()?);
        }

        Ok(Set(vec))
    }

    /// Replaces the entire set with new contents.
    ///
    /// The input Set is deduplicated by the `From<Vec<T>>` conversion.
    fn write(&mut self, value: Set<T>) -> Result<()> {
        let old_len = self.values.len()?;
        let new_len = value.0.len();

        // Clear old positions
        for i in 0..old_len {
            let old_value = self.values[i].read()?;
            self.positions.at_mut(&old_value).delete()?;
        }

        // Write new values and positions (1-indexed)
        for (index, new_value) in value.0.into_iter().enumerate() {
            self.positions
                .at_mut(&new_value)
                .write(checked_position(index)?)?;
            self.values[index].write(new_value)?;
        }

        // Update length
        Slot::<U256>::new(self.values.len_slot(), self.address).write(U256::from(new_len))?;

        // Clear leftover value slots if shrinking
        for i in new_len..old_len {
            self.values[i].delete()?;
        }

        Ok(())
    }

    /// Deletes all elements from the set.
    ///
    /// Clears both the values array and all position entries.
    fn delete(&mut self) -> Result<()> {
        let len = self.len()?;

        // Clear all position entries
        for i in 0..len {
            let value = self.values[i].read()?;
            self.positions.at_mut(&value).delete()?;
        }

        // Delete the underlying vector (clears length and data slots)
        self.values.delete()
    }

    fn t_read(&self) -> Result<Set<T>> {
        Err(TempoPrecompileError::Fatal(
            "Set types don't support transient storage".into(),
        ))
    }

    fn t_write(&mut self, _value: Set<T>) -> Result<()> {
        Err(TempoPrecompileError::Fatal(
            "Set types don't support transient storage".into(),
        ))
    }

    fn t_delete(&mut self) -> Result<()> {
        Err(TempoPrecompileError::Fatal(
            "Set types don't support transient storage".into(),
        ))
    }
}

impl<T> fmt::Debug for SetHandler<T>
where
    T: Storable + StorageKey + Hash + Eq + Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetHandler")
            .field("base_slot", &self.base_slot)
            .field("address", &self.address)
            .finish()
    }
}

impl<T> Clone for SetHandler<T>
where
    T: Storable + StorageKey + Hash + Eq + Clone,
{
    fn clone(&self) -> Self {
        Self::new(self.base_slot, self.address)
    }
}

impl<T> Index<usize> for SetHandler<T>
where
    T: Storable + StorageKey + Hash + Eq + Clone,
{
    type Output = T::Handler;

    /// Returns a reference to the cached handler for the given index (unchecked).
    ///
    /// **WARNING:** Does not check bounds. Caller must ensure that the index is valid.
    /// For checked access use `.at(index)` instead.
    fn index(&self, index: usize) -> &Self::Output {
        &self.values[index]
    }
}


