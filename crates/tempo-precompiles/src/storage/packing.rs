//! Shared utilities for packing and unpacking values in EVM storage slots.
//!
//! This module provides helper functions for bit-level manipulation of storage slots,
//! enabling efficient packing of multiple small values into single 32-byte slots.
//!
//! Packing only applies to primitive types where `LAYOUT::Bytes(count) && count < 32`.
//! Non-primitives (structs, fixed-size arrays, dynamic types) have `LAYOUT = Layout::Slot`.
//!
//! ## Solidity Compatibility
//!
//! This implementation matches Solidity's value packing convention:
//! - Values are right-aligned within their byte range
//! - Types smaller than 32 bytes can pack multiple per slot when dimensions align

use alloy::primitives::U256;

use crate::{
    error::Result,
    storage::{FromWord, Layout, StorableType, StorageOps},
};

/// A helper struct to support packing elements into a single slot. Represents an
/// in-memory storage slot value.
///
/// We used it when we operate on elements that are guaranteed to be packable.
/// To avoid doing multiple storage reads/writes when packing those elements, we
/// use this as an intermediate [`StorageOps`] implementation that can be passed to
/// `Storable::store` and `Storable::load`.
pub struct PackedSlot(pub U256);

impl StorageOps for PackedSlot {
    fn load(&self, _slot: U256) -> Result<U256> {
        Ok(self.0)
    }

    fn store(&mut self, _slot: U256, value: U256) -> Result<()> {
        self.0 = value;
        Ok(())
    }
}

/// Location information for a packed field within a storage slot.
#[derive(Debug, Clone, Copy)]
pub struct FieldLocation {
    /// Offset in slots from the base slot
    pub offset_slots: usize,
    /// Offset in bytes within the target slot
    pub offset_bytes: usize,
    /// Size of the field in bytes
    pub size: usize,
}

impl FieldLocation {
    /// Create a new field location
    #[inline]
    pub const fn new(offset_slots: usize, offset_bytes: usize, size: usize) -> Self {
        Self {
            offset_slots,
            offset_bytes,
            size,
        }
    }
}

/// Create a bit mask for a value of the given byte size.
///
/// For values less than 32 bytes, returns a mask with the appropriate number of bits set.
/// For 32-byte values, returns U256::MAX.
#[inline]
pub fn create_element_mask(byte_count: usize) -> U256 {
    if byte_count >= 32 {
        U256::MAX
    } else {
        (U256::ONE << (byte_count * 8)) - U256::ONE
    }
}

/// Extract a packed value from a storage slot at a given byte offset.
#[inline]
pub fn extract_from_word<T: FromWord + StorableType>(
    slot_value: U256,
    offset: usize,
    bytes: usize,
) -> Result<T> {
    debug_assert!(
        matches!(T::LAYOUT, Layout::Bytes(..)),
        "Packing is only supported by primitive types"
    );

    // Validate that the value doesn't span slot boundaries
    if offset + bytes > 32 {
        return Err(crate::error::TempoPrecompileError::Fatal(format!(
            "Value of {} bytes at offset {} would span slot boundary (max offset: {})",
            bytes,
            offset,
            32 - bytes
        )));
    }

    // Calculate how many bits to shift right to align the value
    let shift_bits = offset * 8;
    let mask = create_element_mask(bytes);

    // Extract and right-align the value
    T::from_word((slot_value >> shift_bits) & mask)
}

/// Insert a packed value into a storage slot at a given byte offset.
#[inline]
pub fn insert_into_word<T: FromWord + StorableType>(
    current: U256,
    value: &T,
    offset: usize,
    bytes: usize,
) -> Result<U256> {
    debug_assert!(
        matches!(T::LAYOUT, Layout::Bytes(..)),
        "Packing is only supported by primitive types"
    );

    // Validate that the value doesn't span slot boundaries
    if offset + bytes > 32 {
        return Err(crate::error::TempoPrecompileError::Fatal(format!(
            "Value of {} bytes at offset {} would span slot boundary (max offset: {})",
            bytes,
            offset,
            32 - bytes
        )));
    }

    // Encode field to its canonical right-aligned U256 representation
    let field_value = value.to_word();

    // Calculate shift and mask
    let shift_bits = offset * 8;
    let mask = create_element_mask(bytes);

    // Clear the bits for this field in the current slot value
    let clear_mask = !(mask << shift_bits);
    let cleared = current & clear_mask;

    // Position the new value and combine with cleared slot
    let positioned = (field_value & mask) << shift_bits;
    Ok(cleared | positioned)
}

/// Zero out a packed value in a storage slot at a given byte offset.
///
/// This is the inverse operation to `insert_into_word`, clearing the bits
/// for a specific field while preserving other packed values in the slot.
#[inline]
pub fn delete_from_word(current: U256, offset: usize, bytes: usize) -> Result<U256> {
    // Validate that the value doesn't span slot boundaries
    if offset + bytes > 32 {
        return Err(crate::error::TempoPrecompileError::Fatal(format!(
            "Value of {} bytes at offset {} would span slot boundary (max offset: {})",
            bytes,
            offset,
            32 - bytes
        )));
    }

    let mask = create_element_mask(bytes);
    let shifted_mask = mask << (offset * 8);
    Ok(current & !shifted_mask)
}

/// Calculate which slot an array element at index `idx` starts in.
///
/// Elements cannot span slot boundaries, so we compute how many elements fit
/// per slot and use that to determine the slot index.
#[inline]
pub const fn calc_element_slot(idx: usize, elem_bytes: usize) -> usize {
    let elems_per_slot = 32 / elem_bytes;
    idx / elems_per_slot
}

/// Calculate the byte offset within a slot for an array element at index `idx`.
///
/// Elements are packed from offset 0 within each slot, with potential unused
/// bytes at slot ends when `elem_bytes` doesn't divide 32 evenly.
#[inline]
pub const fn calc_element_offset(idx: usize, elem_bytes: usize) -> usize {
    let elems_per_slot = 32 / elem_bytes;
    (idx % elems_per_slot) * elem_bytes
}

/// Calculate the element location within a slot for an array element at index `idx`.
#[inline]
pub const fn calc_element_loc(idx: usize, elem_bytes: usize) -> FieldLocation {
    FieldLocation::new(
        calc_element_slot(idx, elem_bytes),
        calc_element_offset(idx, elem_bytes),
        elem_bytes,
    )
}

/// Calculate the total number of slots needed for an array.
///
/// Accounts for wasted bytes at slot ends when elements don't divide 32 evenly.
#[inline]
pub const fn calc_packed_slot_count(n: usize, elem_bytes: usize) -> usize {
    let elems_per_slot = 32 / elem_bytes;
    n.div_ceil(elems_per_slot)
}

/// Test helper function for constructing EVM words from hex string literals.
///
/// Takes an array of hex strings (with or without "0x" prefix), concatenates
/// them left-to-right, left-pads with zeros to 32 bytes, and returns a U256.
///
/// # Example
/// ```ignore
/// let word = gen_word_from(&[
///     "0x2a",                                        // 1 byte
///     "0x1111111111111111111111111111111111111111",  // 20 bytes
///     "0x01",                                        // 1 byte
/// ]);
/// // Produces: [10 zeros] [0x2a] [20 bytes of 0x11] [0x01]
/// ```
#[cfg(any(test, feature = "test-utils"))]
pub fn gen_word_from(values: &[&str]) -> U256 {
    let mut bytes = Vec::new();

    for value in values {
        let hex_str = value.strip_prefix("0x").unwrap_or(value);

        // Parse hex string to bytes
        assert!(
            hex_str.len() % 2 == 0,
            "Hex string '{value}' has odd length"
        );

        for i in (0..hex_str.len()).step_by(2) {
            let byte_str = &hex_str[i..i + 2];
            let byte = u8::from_str_radix(byte_str, 16)
                .unwrap_or_else(|e| panic!("Invalid hex in '{value}': {e}"));
            bytes.push(byte);
        }
    }

    assert!(
        bytes.len() <= 32,
        "Total bytes ({}) exceed 32-byte slot limit",
        bytes.len()
    );

    // Left-pad with zeros to 32 bytes
    let mut slot_bytes = [0u8; 32];
    let start_idx = 32 - bytes.len();
    slot_bytes[start_idx..].copy_from_slice(&bytes);

    U256::from_be_bytes(slot_bytes)
}


