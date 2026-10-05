//! Clique `PoA` consensus for reth.
//!
//! A faithful port of go-ethereum's `consensus/clique` (EIP-225), extended to
//! support modern EVM hardforks (Shanghai, Cancun, Prague, Amsterdam) which
//! upstream geth clique hard-rejects. See [`consensus`] for the exact rule
//! differences.
//!
//! Derived from go-ethereum v1.13.15 `consensus/clique` (LGPL-3.0).
//! Copyright 2017 The go-ethereum Authors. This crate is licensed under
//! LGPL-3.0-or-later accordingly.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod consensus;
/// Clique consensus error types.
pub mod error;
/// Seal hash computation and signer recovery (`CliqueRLP`).
pub mod seal;
/// Vote snapshots (geth's clique `Snapshot` port).
pub mod snapshot;

pub use consensus::{CliqueConsensus, CliqueHeaderSource};
pub use error::CliqueError;
pub use snapshot::{Snapshot, Tally, Vote};

use alloy_primitives::{B64, U256};

/// Fixed number of extra-data prefix bytes reserved for signer vanity.
pub const EXTRA_VANITY: usize = 32;
/// Fixed number of extra-data suffix bytes reserved for the signer seal
/// (a 65-byte secp256k1 signature).
pub const EXTRA_SEAL: usize = 65;
/// Length of an address in bytes (checkpoint signer list unit).
pub const ADDR_LENGTH: usize = 20;
/// Default number of blocks after which to checkpoint and reset pending votes.
pub const DEFAULT_EPOCH_LENGTH: u64 = 30000;
/// Number of blocks after which the vote snapshot is persisted (geth: 1024).
pub const CHECKPOINT_INTERVAL: u64 = 1024;
/// Random delay unit (per signer) to allow concurrent signers, in milliseconds
/// (geth `wiggleTime`).
pub const WIGGLE_TIME_MS: u64 = 500;

/// Magic nonce value to vote on adding a new signer (`0xff..ff`).
pub const NONCE_AUTH_VOTE: B64 = B64::new([0xff; 8]);
/// Magic nonce value to vote on removing a signer (`0x00..00`).
pub const NONCE_DROP_VOTE: B64 = B64::ZERO;

/// Difficulty of a block signed by the in-turn signer (`DIFF_INTURN`).
pub const DIFF_INTURN: U256 = U256::from_limbs([2, 0, 0, 0]);
/// Difficulty of a block signed by an out-of-turn signer (`DIFF_NOTURN`).
pub const DIFF_NOTURN: U256 = U256::from_limbs([1, 0, 0, 0]);

/// Clique chain configuration — geth's `params.CliqueConfig`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CliqueConfig {
    /// Minimum time between consecutive blocks, in seconds.
    pub period: u64,
    /// Number of blocks after which to checkpoint and reset pending votes.
    pub epoch: u64,
    /// Timestamp at which the clique extension precompiles activate
    /// (genesis config key `cliquePrecompileTime`). `None` = never.
    pub precompile_time: Option<u64>,
    /// Timestamp at which the T0 precompile suite activates and the fork
    /// state seeding runs (genesis config key `t0Time`). `None` = never.
    pub t0_time: Option<u64>,
    /// Fork-gated clique period change (genesis config key
    /// `cliquePeriodChange`: `{"time": <ts>, "period": <seconds>}`).
    /// `None` = period never changes.
    pub period_change: Option<(u64, u64)>,
}

impl CliqueConfig {
    /// Creates a config, normalizing `epoch == 0` to the default epoch length
    /// (mirrors geth `clique.New`).
    pub const fn new(period: u64, epoch: u64) -> Self {
        Self {
            period,
            epoch: if epoch == 0 { DEFAULT_EPOCH_LENGTH } else { epoch },
            precompile_time: None,
            t0_time: None,
            period_change: None,
        }
    }

    /// Returns the clique period in effect at the given timestamp
    /// (fork-gated via `cliquePeriodChange`).
    pub const fn period_at(&self, timestamp: u64) -> u64 {
        match self.period_change {
            Some((at, period)) if timestamp >= at => period,
            _ => self.period,
        }
    }

    /// Sets the clique precompile activation timestamp (builder style).
    pub const fn with_precompile_time(mut self, precompile_time: Option<u64>) -> Self {
        self.precompile_time = precompile_time;
        self
    }

    /// Sets the T0 suite activation timestamp (builder style).
    pub const fn with_t0_time(mut self, t0_time: Option<u64>) -> Self {
        self.t0_time = t0_time;
        self
    }

    /// Sets the fork-gated period change (builder style).
    pub const fn with_period_change(mut self, period_change: Option<(u64, u64)>) -> Self {
        self.period_change = period_change;
        self
    }

    /// Returns `true` if the given block number is an epoch checkpoint.
    pub const fn is_checkpoint(&self, number: u64) -> bool {
        number.is_multiple_of(self.epoch)
    }
}

#[cfg(test)]
/// Shared test helpers: real secp256k1 signing for seal/recovery round-trips.
pub(crate) mod test_util {
    use alloy_consensus::Header;
    use alloy_primitives::{address, b256, Address, B256};
    use alloy_signer_local::PrivateKeySigner;

    /// Fixed test key (0x4242…42).
    pub(crate) const TEST_SIGNER_KEY: B256 =
        b256!("4242424242424242424242424242424242424242424242424242424242424242");
    /// Address of [`TEST_SIGNER_KEY`] (verified against geth's key derivation).
    pub(crate) const TEST_SIGNER_ADDR: Address = address!("17c5185167401ed00cf5f5b2fc97d9bbfdb7d025");

    /// Returns the fixed test signer.
    pub(crate) fn test_signer() -> PrivateKeySigner {
        PrivateKeySigner::from_bytes(&TEST_SIGNER_KEY).unwrap()
    }

    /// Signs the header exactly like geth's clique `Seal`: keccak(CliqueRLP),
    /// 65-byte signature (v ∈ {0,1}) copied into the extraData tail. The
    /// header's extraData must already reserve the 65-byte seal space.
    pub(crate) fn seal_sign(header: &Header) -> Header {
        use crate::seal::seal_hash;
        use alloy_signer::SignerSync;

        let sig = test_signer().sign_hash_sync(&seal_hash(header)).unwrap();
        // `as_rsy` yields v ∈ {0,1} (geth clique convention); `as_bytes` would
        // produce Electrum-style v ∈ {27,28}
        let sig65 = sig.as_rsy();
        let mut extra = header.extra_data.to_vec();
        let len = extra.len();
        extra[len - 65..].copy_from_slice(&sig65);
        let mut signed = header.clone();
        signed.extra_data = extra.into();
        signed
    }
}
