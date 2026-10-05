//! Bytes-like (`Bytes`, `String`) implementation for the storage traits.
//!
//! # Storage Layout
//!
//! Bytes-like types use Solidity-compatible:
//! **Short strings (≤31 bytes)** are stored inline in a single slot:
//! - Bytes 0..len: UTF-8 string data (left-aligned)
//! - Byte 31 (LSB): length * 2 (bit 0 = 0 indicates short string)
//!
//! **Long strings (≥32 bytes)** use keccak256-based storage:
//! - Base slot: stores `length * 2 + 1` (bit 0 = 1 indicates long string)
//! - Data slots: stored at `keccak256(main_slot) + i` for each 32-byte chunk

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{StorageCtx, StorageOps, types::*},
};
use alloy::primitives::{Address, Bytes, U256, keccak256};
use std::marker::PhantomData;

impl StorableType for Bytes {
    const LAYOUT: Layout = Layout::Slots(1);
    const IS_DYNAMIC: bool = true;
    type Handler = BytesLikeHandler<Self>;

    fn handle(slot: U256, _ctx: LayoutCtx, address: Address) -> Self::Handler {
        BytesLikeHandler::new(slot, address)
    }
}

impl StorableType for String {
    const LAYOUT: Layout = Layout::Slots(1);
    const IS_DYNAMIC: bool = true;
    type Handler = BytesLikeHandler<Self>;

    fn handle(slot: U256, _ctx: LayoutCtx, address: Address) -> Self::Handler {
        BytesLikeHandler::new(slot, address)
    }
}

// -- BYTES-LIKE HANDLER -------------------------------------------------------

/// Handler for bytes-like types (`Bytes`, `String`) that provides efficient length queries.
#[derive(Debug, Clone)]
pub struct BytesLikeHandler<T> {
    base_slot: U256,
    address: Address,
    _ty: PhantomData<T>,
}

impl<T: Storable> BytesLikeHandler<T> {
    /// Creates a new handler for the bytes-like value at the given base slot.
    #[inline]
    pub fn new(base_slot: U256, address: Address) -> Self {
        Self {
            base_slot,
            address,
            _ty: PhantomData,
        }
    }

    #[inline]
    fn as_slot(&self) -> Slot<T> {
        Slot::new(self.base_slot, self.address)
    }

    /// Returns the byte length without loading all data (only reads base slot).
    #[inline]
    pub fn len(&self) -> Result<usize> {
        let base_value = Slot::<U256>::new(self.base_slot, self.address).read()?;
        let is_long = is_long_string(base_value);
        calc_string_length(base_value, is_long)
    }

    /// Returns whether the stored value is empty.
    #[inline]
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}

impl<T: Storable> Handler<T> for BytesLikeHandler<T> {
    #[inline]
    fn read(&self) -> Result<T> {
        self.as_slot().read()
    }

    #[inline]
    fn write(&mut self, value: T) -> Result<()> {
        self.as_slot().write(value)
    }

    #[inline]
    fn delete(&mut self) -> Result<()> {
        self.as_slot().delete()
    }

    #[inline]
    fn t_read(&self) -> Result<T> {
        self.as_slot().t_read()
    }

    #[inline]
    fn t_write(&mut self, value: T) -> Result<()> {
        self.as_slot().t_write(value)
    }

    #[inline]
    fn t_delete(&mut self) -> Result<()> {
        self.as_slot().t_delete()
    }
}

// -- STORABLE OPS IMPLEMENTATIONS ---------------------------------------------

impl Storable for Bytes {
    #[inline]
    fn load<S: StorageOps>(storage: &S, slot: U256, ctx: LayoutCtx) -> Result<Self> {
        debug_assert!(ctx.is_full(), "Bytes cannot be packed");
        load_bytes_like(storage, slot, |data| Ok(Self::from(data)))
    }

    #[inline]
    fn store<S: StorageOps>(&self, storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert!(ctx.is_full(), "Bytes cannot be packed");
        store_bytes_like(self.as_ref(), storage, slot, ctx)
    }

    /// Custom delete for bytes-like types: clears keccak256-addressed data slots for long values.
    #[inline]
    fn delete<S: StorageOps>(storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert!(ctx.is_full(), "Bytes cannot be packed");
        delete_bytes_like(storage, slot)
    }
}

impl Storable for String {
    #[inline]
    fn load<S: StorageOps>(storage: &S, slot: U256, ctx: LayoutCtx) -> Result<Self> {
        debug_assert!(ctx.is_full(), "String cannot be packed");
        load_bytes_like(storage, slot, |data| {
            Self::from_utf8(data).map_err(|e| {
                TempoPrecompileError::Fatal(format!("Invalid UTF-8 in stored string: {e}"))
            })
        })
    }

    #[inline]
    fn store<S: StorageOps>(&self, storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert!(ctx.is_full(), "String cannot be packed");
        store_bytes_like(self.as_bytes(), storage, slot, ctx)
    }

    /// Custom delete for bytes-like types: clears keccak256-addressed data slots for long values.
    #[inline]
    fn delete<S: StorageOps>(storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert!(ctx.is_full(), "String cannot be packed");
        delete_bytes_like(storage, slot)
    }
}

// -- HELPER FUNCTIONS ---------------------------------------------------------

/// Generic load implementation for string-like types (String, Bytes) using Solidity's encoding.
#[inline]
fn load_bytes_like<T, S, F>(storage: &S, base_slot: U256, into: F) -> Result<T>
where
    S: StorageOps,
    F: FnOnce(Vec<u8>) -> Result<T>,
{
    let base_value = storage.load(base_slot)?;
    let is_long = is_long_string(base_value);
    let length = calc_string_length(base_value, is_long)?;

    if is_long {
        // Long string: read data from keccak256(base_slot) + i
        let slot_start = calc_data_slot(base_slot);
        let chunks = calc_chunks(length);
        let mut data = Vec::new();

        for i in 0..chunks {
            let slot = slot_start + U256::from(i);
            let chunk_value = storage.load(slot)?;
            let chunk_bytes = chunk_value.to_be_bytes::<32>();

            // For the last chunk, only take the remaining bytes
            let bytes_to_take = if i == chunks - 1 {
                length - (i * 32)
            } else {
                32
            };
            data.extend_from_slice(&chunk_bytes[..bytes_to_take]);
        }

        into(data)
    } else {
        // Short string: data is inline in the main slot
        let bytes = base_value.to_be_bytes::<32>();
        into(bytes[..length].to_vec())
    }
}

/// Generic store implementation for byte-like types (String, Bytes) using Solidity's encoding.
/// On T5+ performs tail cleanup when the prior value was long and the new one takes fewer slots.
#[inline]
fn store_bytes_like<S: StorageOps>(
    bytes: &[u8],
    storage: &mut S,
    base_slot: U256,
    ctx: LayoutCtx,
) -> Result<()> {
    let new_len = bytes.len();
    let new_is_long = new_len > 31;
    let mut data_slot: Option<U256> = None;

    // (T5+) Cleanup stale tail if necessary.
    if !ctx.skip_tail_cleanup() && StorageCtx.spec().is_t5() {
        let prev = storage.load(base_slot)?;
        // Only applicable to long strings, as short ones always get overridden.
        if is_long_string(prev) {
            let prev_chunks = calc_chunks(calc_string_length(prev, true)?);
            let new_chunks = if new_is_long { calc_chunks(new_len) } else { 0 };
            if prev_chunks > new_chunks {
                let slot_start = calc_data_slot(base_slot);
                for i in new_chunks..prev_chunks {
                    storage.store(slot_start + U256::from(i), U256::ZERO)?;
                }
                data_slot = Some(slot_start);
            }
        }
    }

    if !new_is_long {
        storage.store(base_slot, encode_short_string(bytes))
    } else {
        storage.store(base_slot, encode_long_string_length(new_len))?;

        // Store data in chunks at keccak256(base_slot) + i
        let slot_start = data_slot.unwrap_or_else(|| calc_data_slot(base_slot));
        for (i, chunk) in bytes.chunks(32).enumerate() {
            let slot = slot_start + U256::from(i);

            // Pad chunk to 32 bytes if it's the last chunk
            let mut chunk_bytes = [0u8; 32];
            chunk_bytes[..chunk.len()].copy_from_slice(chunk);

            storage.store(slot, U256::from_be_bytes(chunk_bytes))?;
        }

        Ok(())
    }
}

/// Generic delete implementation for byte-like types (String, Bytes) using Solidity's encoding.
///
/// Clears both the main slot and any keccak256-addressed data slots for long strings.
#[inline]
fn delete_bytes_like<S: StorageOps>(storage: &mut S, base_slot: U256) -> Result<()> {
    let base_value = storage.load(base_slot)?;
    let is_long = is_long_string(base_value);

    if is_long {
        // Long string: need to clear data slots as well
        let length = calc_string_length(base_value, true)?;
        let slot_start = calc_data_slot(base_slot);
        let chunks = calc_chunks(length);

        // Clear all data slots
        for i in 0..chunks {
            let slot = slot_start + U256::from(i);
            storage.store(slot, U256::ZERO)?;
        }
    }

    // Clear the main slot
    storage.store(base_slot, U256::ZERO)
}

/// Compute the storage slot where long string data begins.
///
/// For long strings (≥32 bytes), data is stored starting at `keccak256(base_slot)`.
#[inline]
fn calc_data_slot(base_slot: U256) -> U256 {
    U256::from_be_bytes(keccak256(base_slot.to_be_bytes::<32>()).0)
}

/// Check if a storage slot value represents a long string.
///
/// Solidity string encoding uses bit 0 of the LSB to distinguish:
/// - Bit 0 = 0: Short string (≤31 bytes)
/// - Bit 0 = 1: Long string (≥32 bytes)
#[inline]
fn is_long_string(slot_value: U256) -> bool {
    (slot_value.byte(0) & 1) != 0
}

/// Extract and validate the string length from a storage slot value.
///
/// Returns an error if the decoded length overflows `usize` or a short-string length exceeds 31.
#[inline]
fn calc_string_length(slot_value: U256, is_long: bool) -> Result<usize> {
    if is_long {
        // Long string: slot stores (length * 2 + 1)
        // Extract length: (value - 1) / 2
        let length_times_two_plus_one: U256 = slot_value;
        let length_times_two: U256 = length_times_two_plus_one - U256::ONE;
        let length_u256: U256 = length_times_two >> 1;
        if length_u256 > U256::from(u32::MAX) {
            return Err(TempoPrecompileError::under_overflow());
        }
        Ok(length_u256.to::<usize>())
    } else {
        // Short string: LSB stores (length * 2)
        // Extract length: LSB / 2
        let bytes = slot_value.to_be_bytes::<32>();
        let length = (bytes[31] / 2) as usize;
        if length > 31 {
            // Unreachable unless the state has been tampered
            return Err(TempoPrecompileError::Fatal(format!(
                "short string length {length} exceeds maximum of 31 bytes"
            )));
        }
        Ok(length)
    }
}

/// Compute the number of 32-byte chunks needed to store a byte string.
#[inline]
fn calc_chunks(byte_length: usize) -> usize {
    byte_length.div_ceil(32)
}

/// Encode a short string (≤31 bytes) into a U256 for inline storage.
///
/// Format: bytes left-aligned, LSB contains (length * 2)
#[inline]
fn encode_short_string(bytes: &[u8]) -> U256 {
    let mut storage_bytes = [0u8; 32];
    storage_bytes[..bytes.len()].copy_from_slice(bytes);
    storage_bytes[31] = (bytes.len() * 2) as u8;
    U256::from_be_bytes(storage_bytes)
}

/// Encode the length metadata for a long string (≥32 bytes).
///
/// Returns `length * 2 + 1` where bit 0 = 1 indicates long string storage.
#[inline]
fn encode_long_string_length(byte_length: usize) -> U256 {
    U256::from(byte_length * 2 + 1)
}


