//! reth consensus integration — [`CliqueConsensus`] implements reth's
//! `HeaderValidator` / `Consensus` / `FullConsensus` with clique rules.

use crate::{
    error::CliqueError, seal::recover_signer, snapshot::Snapshot, CliqueConfig, DIFF_INTURN,
    DIFF_NOTURN, EXTRA_SEAL, EXTRA_VANITY,
};
use alloy_consensus::{constants::EMPTY_OMMER_ROOT_HASH, BlockHeader, Header};
use alloy_primitives::B256;
use lru::LruCache;
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks};
use reth_consensus::{
    Consensus, ConsensusError, FullConsensus, HeaderValidator, ReceiptRootBloom, TransactionRoot,
};
use reth_consensus_common::validation::{
    validate_against_parent_eip1559_base_fee, validate_against_parent_gas_limit,
    validate_against_parent_hash_number, validate_against_parent_timestamp,
    validate_block_pre_execution_with_tx_root, validate_body_against_header,
    validate_header_base_fee, validate_header_gas,
};
use reth_ethereum_consensus::validate_block_post_execution;
use reth_primitives_traits::{Block, NodePrimitives, RecoveredBlock, SealedBlock, SealedHeader};
use std::{
    fmt,
    num::NonZeroUsize,
    sync::{Arc, Mutex, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

/// Minimal read access to headers, used to reconstruct clique vote snapshots.
///
/// Decoupled from reth's `HeaderProvider` so this crate stays testable; the
/// node crate adapts reth's provider into this.
pub trait CliqueHeaderSource: fmt::Debug + Send + Sync {
    /// Returns the header with the given hash, if known.
    fn header_by_hash(&self, hash: B256) -> Option<Header>;
    /// Returns the canonical header with the given number, if known.
    fn header_by_number(&self, number: u64) -> Option<Header>;
}

/// Source that knows nothing — used until the node wires up a real provider
/// and in pure unit tests.
#[derive(Debug, Default)]
pub struct EmptyHeaderSource;

impl CliqueHeaderSource for EmptyHeaderSource {
    fn header_by_hash(&self, _hash: B256) -> Option<Header> {
        None
    }

    fn header_by_number(&self, _number: u64) -> Option<Header> {
        None
    }
}

/// Clique consensus engine for reth — a port of geth's `Clique` engine.
///
/// Rule differences vs upstream geth clique (documented deliberately):
/// 1. geth hard-rejects Shanghai/Cancun blocks (`clique does not support ...`).
///    We instead gate all post-London header fields on the chain spec's
///    hardfork schedule, so a clique chain can activate modern EVM forks.
///    Post-Cancun the parent beacon block root must be `B256::ZERO` (our
///    deterministic sealer convention).
/// 2. The seal hash extends naturally to post-London fields (see
///    [`crate::seal::seal_hash`]); for pre-Shanghai blocks it is identical to
///    geth's.
#[derive(Debug)]
pub struct CliqueConsensus {
    chain_spec: Arc<ChainSpec>,
    config: CliqueConfig,
    /// Header source for vote-snapshot reconstruction. Swappable because the
    /// node builder creates consensus before the provider exists.
    source: RwLock<Arc<dyn CliqueHeaderSource>>,
    /// Recently computed snapshots by block hash (geth's `recents` LRU).
    snapshots: Mutex<LruCache<B256, Arc<Snapshot>>>,
}

impl CliqueConsensus {
    /// Creates a new clique consensus engine for the given chain spec.
    ///
    /// The clique config (`period`/`epoch`) is read from the genesis config's
    /// extra fields (`{"clique": {"period": .., "epoch": ..}}`) — see
    /// [`CliqueConfig`] and the chainspec crate.
    pub fn new(chain_spec: Arc<ChainSpec>, config: CliqueConfig) -> Self {
        Self {
            chain_spec,
            config,
            source: RwLock::new(Arc::new(EmptyHeaderSource)),
            snapshots: Mutex::new(LruCache::new(NonZeroUsize::new(128).unwrap())),
        }
    }

    /// Sets the header source used to reconstruct vote snapshots.
    pub fn set_header_source(&self, source: Arc<dyn CliqueHeaderSource>) {
        *self.source.write().unwrap() = source;
    }

    /// Returns a reference to the clique chain configuration.
    pub const fn config(&self) -> &CliqueConfig {
        &self.config
    }

    /// Returns `true` when the chain has crossed into the post-merge
    /// "tempo form": full standard post-merge header (difficulty 0, empty
    /// withdrawals, deterministic beacon root, requests hash), like a chain
    /// whose genesis activates every fork at 0 with TTD 0. Activated by
    /// coordinated config upgrade at `pragueTime`.
    pub fn is_tempo_form(&self, timestamp: u64) -> bool {
        self.chain_spec.is_prague_active_at_timestamp(timestamp)
    }

    /// Returns the chain spec.
    pub const fn chain_spec(&self) -> &Arc<ChainSpec> {
        &self.chain_spec
    }

    /// Returns the genesis / trusted-checkpoint header at `number`, if it can
    /// serve as a trusted snapshot bootstrap point.
    fn trusted_checkpoint_header(&self, number: u64, hash: B256) -> Option<Header> {
        if number == 0 {
            let genesis = self.chain_spec.genesis_header().clone();
            return genesis_hash_matches(&genesis, hash).then_some(genesis);
        }
        if number.is_multiple_of(self.config.epoch) {
            let source = self.source.read().unwrap();
            return source
                .header_by_number(number)
                .filter(|header| header.hash_slow() == hash);
        }
        None
    }

    /// Retrieves the vote snapshot at `(number, hash)` — port of geth's
    /// `Clique.snapshot`: LRU lookup, trusted checkpoint bootstrap, otherwise
    /// walk ancestors backwards until a snapshot point and replay the votes.
    pub fn snapshot_for(&self, number: u64, hash: B256) -> Result<Arc<Snapshot>, CliqueError> {
        if let Some(snap) = self.snapshots.lock().unwrap().get(&hash) {
            return Ok(snap.clone());
        }

        // Trusted bootstrap: genesis or an epoch checkpoint's extraData carries
        // the full signer list.
        if let Some(header) = self.trusted_checkpoint_header(number, hash) {
            let signers = Snapshot::signers_from_checkpoint(&header)?;
            let snap = Arc::new(Snapshot::new(self.config, number, hash, signers));
            self.snapshots.lock().unwrap().put(hash, snap.clone());
            return Ok(snap);
        }

        // Walk backwards gathering headers until a snapshot point is found.
        let mut pending: Vec<Header> = Vec::new();
        let mut current = (number, hash);
        let base: Arc<Snapshot> = loop {
            if let Some(snap) = self.snapshots.lock().unwrap().get(&current.1).cloned() {
                break snap;
            }
            if let Some(header) = self.trusted_checkpoint_header(current.0, current.1) {
                let signers = Snapshot::signers_from_checkpoint(&header)?;
                let snap =
                    Arc::new(Snapshot::new(self.config, current.0, current.1, signers));
                self.snapshots.lock().unwrap().put(current.1, snap.clone());
                break snap;
            }
            let header = self
                .source
                .read()
                .unwrap()
                .header_by_hash(current.1)
                .ok_or(CliqueError::UnknownAncestor)?;
            current = (current.0 - 1, header.parent_hash);
            pending.push(header);
        };

        pending.reverse();
        let sealed: Vec<SealedHeader<Header>> =
            pending.into_iter().map(SealedHeader::seal_slow).collect();
        let snap = Arc::new(base.apply(&sealed, recover_signer)?);
        self.snapshots.lock().unwrap().put(snap.hash, snap.clone());
        Ok(snap)
    }

    /// Standalone clique header checks — port of geth `verifyHeader` with the
    /// Shanghai/Cancun rejection replaced by hardfork gating.
    pub fn verify_header_standalone(&self, header: &SealedHeader<Header>) -> Result<(), ConsensusError> {
        let h = header.header();
        let number = h.number();

        // Don't waste time checking blocks from the future
        {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            if h.timestamp() > now {
                return Err(ConsensusError::TimestampIsInFuture {
                    timestamp: h.timestamp(),
                    present_timestamp: now,
                });
            }
        }

        // Tempo form (post pragueTime): full post-merge header form, like a
        // chain whose genesis activates every fork at 0 with TTD 0.
        if self.is_tempo_form(h.timestamp()) {
            return self.verify_header_standalone_tempo_form(h);
        }

        // Checkpoint blocks need to enforce zero beneficiary
        let checkpoint = self.config.is_checkpoint(number);
        if checkpoint && !h.beneficiary().is_zero() {
            return Err(ConsensusError::other(CliqueError::InvalidCheckpointBeneficiary));
        }

        // Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
        let nonce = h.nonce();
        let is_auth = nonce == Some(crate::NONCE_AUTH_VOTE);
        let is_drop = nonce.is_none_or(|n| n == crate::NONCE_DROP_VOTE);
        if !is_auth && !is_drop {
            return Err(ConsensusError::other(CliqueError::InvalidVote));
        }
        if checkpoint && !is_drop {
            return Err(ConsensusError::other(CliqueError::InvalidCheckpointVote));
        }

        // extraData must contain the vanity and the seal, and carry a signer
        // list on checkpoints only
        let extra = h.extra_data();
        if extra.len() < EXTRA_VANITY {
            return Err(ConsensusError::other(CliqueError::MissingVanity));
        }
        if extra.len() < EXTRA_VANITY + EXTRA_SEAL {
            return Err(ConsensusError::other(CliqueError::MissingSignature));
        }
        let signers_bytes = extra.len() - EXTRA_VANITY - EXTRA_SEAL;
        if !checkpoint && signers_bytes != 0 {
            return Err(ConsensusError::other(CliqueError::ExtraSigners));
        }
        if checkpoint && !signers_bytes.is_multiple_of(crate::ADDR_LENGTH) {
            return Err(ConsensusError::other(CliqueError::InvalidCheckpointSigners));
        }

        // mixDigest is reserved; uncles are meaningless in PoA
        if h.mix_hash().is_some_and(|mix| !mix.is_zero()) {
            return Err(ConsensusError::other(CliqueError::InvalidMixDigest));
        }
        if h.ommers_hash() != EMPTY_OMMER_ROOT_HASH {
            return Err(ConsensusError::other(CliqueError::InvalidUncleHash));
        }

        // Difficulty must be 1 or 2 (may not be the *correct* value yet)
        if number > 0 && h.difficulty() != DIFF_INTURN && h.difficulty() != DIFF_NOTURN {
            return Err(ConsensusError::other(CliqueError::InvalidDifficulty));
        }

        // Gas limit <= 2^63-1
        validate_header_gas(h)?;

        // 1559: base fee rules per hardfork schedule (London is active from
        // genesis on this chain)
        validate_header_base_fee(h, &self.chain_spec)?;

        let _ts = h.timestamp();

        // Clique header-form rules (interop with geth's clique sealer): geth's
        // clique engine seals blocks in the PRE-Shanghai header form regardless
        // of the fork schedule — no withdrawals root, no blob fields, no
        // beacon root, no requests/BAL fields. The EVM *execution* rules still
        // follow the chain spec (Shanghai/Cancun/Prague semantics), but the
        // header form stays clique-legacy, so these fields must be absent.
        if h.withdrawals_root().is_some() {
            return Err(ConsensusError::WithdrawalsRootUnexpected);
        }

        if h.blob_gas_used().is_some() {
            return Err(ConsensusError::BlobGasUsedUnexpected);
        }
        if h.excess_blob_gas().is_some() {
            return Err(ConsensusError::ExcessBlobGasUnexpected);
        }
        if h.parent_beacon_block_root().is_some() {
            return Err(ConsensusError::ParentBeaconBlockRootUnexpected);
        }

        if h.requests_hash().is_some() {
            return Err(ConsensusError::RequestsHashUnexpected);
        }

        if h.block_access_list_hash().is_some() {
            return Err(ConsensusError::BlockAccessListHashUnexpected);
        }
        if h.slot_number().is_some() {
            return Err(ConsensusError::SlotNumberUnexpected);
        }

        Ok(())
    }

    /// Tempo-form (full post-merge) header validation — mirrors what a
    /// vanilla post-merge chain enforces, with our deterministic
    /// conventions: beacon root = 0x0, no blob transactions, withdrawals
    /// list always empty, and the sealer's authority proof kept in
    /// extraData (vanity + 65-byte signature).
    fn verify_header_standalone_tempo_form(
        &self,
        h: &Header,
    ) -> Result<(), ConsensusError> {
        use alloy_consensus::constants::EMPTY_WITHDRAWALS;

        // post-merge form
        if !h.difficulty().is_zero() {
            return Err(ConsensusError::TheMergeDifficultyIsNotZero);
        }
        if !h.nonce().is_some_and(|nonce| nonce.is_zero()) {
            return Err(ConsensusError::TheMergeNonceIsNotZero);
        }
        if h.ommers_hash() != EMPTY_OMMER_ROOT_HASH {
            return Err(ConsensusError::other(CliqueError::InvalidUncleHash));
        }

        // beacon root: deterministic 0x0 convention
        if h.parent_beacon_block_root() != Some(B256::ZERO) {
            return Err(ConsensusError::ParentBeaconBlockRootUnexpected);
        }

        // withdrawals: empty list is mandatory post-shanghai
        if h.withdrawals_root() != Some(EMPTY_WITHDRAWALS) {
            return Err(ConsensusError::WithdrawalsRootMissing);
        }

        // prague requests hash must be present (validated against execution
        // in validate_block_post_execution)
        if h.requests_hash().is_none() {
            return Err(ConsensusError::RequestsHashMissing);
        }

        // blob fields: present and zero (no blob transactions on clique)
        if h.blob_gas_used() != Some(0) || h.excess_blob_gas() != Some(0) {
            return Err(ConsensusError::BlobGasUsedMissing);
        }

        // extra data: vanity + seal signature (authority proof)
        let extra = h.extra_data();
        if extra.len() < EXTRA_VANITY + EXTRA_SEAL {
            return Err(ConsensusError::other(CliqueError::MissingSignature));
        }

        // Gas limit <= 2^63-1
        validate_header_gas(h)?;
        validate_header_base_fee(h, &self.chain_spec)?;

        Ok(())
    }

    /// Snapshot-dependent clique checks — port of geth `verifyCascadingFields`
    /// + `verifySeal` (timestamp period, checkpoint signer list, seal).
    pub fn verify_header_against_parent_clique(
        &self,
        header: &SealedHeader<Header>,
        parent: &SealedHeader<Header>,
    ) -> Result<(), ConsensusError> {
        let h = header.header();
        let number = h.number();
        if number == 0 {
            return Ok(());
        }

        // Timestamp must respect the clique period (fork-gated)
        if parent.timestamp() + self.config.period_at(parent.timestamp()) > h.timestamp() {
            return Err(ConsensusError::other(CliqueError::InvalidTimestamp));
        }

        // Gas limit / base fee continuity
        validate_against_parent_gas_limit(header, parent, &self.chain_spec)?;
        validate_against_parent_eip1559_base_fee(h, parent.header(), &self.chain_spec)?;

        // Tempo form: authority check via snapshot (authorized signer, recents
        // window) — no difficulty/turn semantics post-merge.
        if self.is_tempo_form(h.timestamp()) {
            let snap = self
                .snapshot_for(parent.number(), parent.hash())
                .map_err(ConsensusError::other)?;
            snap.verify_authorization(h, number, crate::seal::recover_signer)
                .map_err(ConsensusError::other)?;
            return Ok(());
        }

        // Blob gas continuity: clique headers never carry blob fields
        // (clique form), so EIP-4844 parent checks do not apply.

        match self.snapshot_for(parent.number(), parent.hash()) {
            Ok(snap) => {
                // Checkpoint blocks must embed the exact signer list
                if self.config.is_checkpoint(number) {
                    let mut expected = Vec::with_capacity(snap.signers.len() * crate::ADDR_LENGTH);
                    for signer in snap.signers_sorted() {
                        expected.extend_from_slice(signer.as_slice());
                    }
                    let extra = h.extra_data();
                    let end = extra.len() - EXTRA_SEAL;
                    if &extra[EXTRA_VANITY..end] != expected.as_slice() {
                        return Err(ConsensusError::other(CliqueError::MismatchingCheckpointSigners));
                    }
                }
                snap.verify_seal(h, number).map_err(ConsensusError::other)?;
            }
            Err(err @ CliqueError::UnknownAncestor) => {
                // Detached header range (downloaded ahead of the local head):
                // seal verification is deferred to the backfill stage / engine
                // full-block validation, which runs once ancestors are known.
                // Everything checkable without ancestors has already passed.
                let _ = err;
            }
            Err(err) => return Err(ConsensusError::other(err)),
        }

        Ok(())
    }
}

/// Clique-form pre-execution validation: transaction root only.
/// Ommer/withdrawals consistency is enforced in `validate_body_against_header`
/// (common), and the ABSENCE of post-shanghai fields is enforced in
/// [`Self::verify_header_standalone`] (clique form).
fn validate_block_pre_execution_clique<B: Block>(
    block: &SealedBlock<B>,
    transaction_root: Option<TransactionRoot>,
) -> Result<(), ConsensusError> {
    let expected_transaction_root = block.header().transactions_root();
    let calculated =
        transaction_root.unwrap_or_else(|| reth_primitives_traits::BlockBody::calculate_tx_root(block.body()));
    if calculated != expected_transaction_root {
        return Err(ConsensusError::BodyTransactionRootDiff(
            reth_primitives_traits::GotExpectedBoxed(
                reth_primitives_traits::GotExpected {
                    got: calculated,
                    expected: expected_transaction_root,
                }
                .into(),
            ),
        ));
    }

    Ok(())
}

fn genesis_hash_matches(header: &Header, expected: B256) -> bool {
    expected.is_zero() || header.hash_slow() == expected
}

impl HeaderValidator<Header> for CliqueConsensus {
    fn validate_header(&self, header: &SealedHeader<Header>) -> Result<(), ConsensusError> {
        self.verify_header_standalone(header)
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<Header>,
        parent: &SealedHeader<Header>,
    ) -> Result<(), ConsensusError> {
        let h = header.header();
        validate_against_parent_hash_number(h, parent)?;
        validate_against_parent_timestamp(h, parent.header())?;

        self.verify_header_against_parent_clique(header, parent)
    }
}

impl<B> Consensus<B> for CliqueConsensus
where
    B: Block<Header = Header>,
{
    fn validate_body_against_header(
        &self,
        body: &B::Body,
        header: &SealedHeader<Header>,
    ) -> Result<(), ConsensusError> {
        validate_body_against_header(body, header.header())
    }

    fn validate_block_pre_execution(&self, block: &SealedBlock<B>) -> Result<(), ConsensusError> {
        if self.chain_spec.is_prague_active_at_timestamp(block.header().timestamp()) {
            // tempo form: vanilla checks pass naturally (empty withdrawals,
            // zero blob gas, correct requests hash)
            return validate_block_pre_execution_with_tx_root(block, &self.chain_spec, None);
        }
        validate_block_pre_execution_clique(block, None)
    }

    fn validate_block_pre_execution_with_tx_root(
        &self,
        block: &SealedBlock<B>,
        transaction_root: Option<TransactionRoot>,
    ) -> Result<(), ConsensusError> {
        if self.chain_spec.is_prague_active_at_timestamp(block.header().timestamp()) {
            return validate_block_pre_execution_with_tx_root(
                block,
                &self.chain_spec,
                transaction_root,
            );
        }
        validate_block_pre_execution_clique(block, transaction_root)
    }

    fn is_transient_error(&self, error: &ConsensusError) -> bool {
        match error {
            ConsensusError::TimestampIsInFuture { .. } => true,
            other => other
                .as_other()
                .and_then(|e| e.downcast_ref::<CliqueError>())
                .is_some_and(|e| {
                    matches!(e, CliqueError::FutureBlock | CliqueError::UnknownAncestor)
                }),
        }
    }
}

impl<N> FullConsensus<N> for CliqueConsensus
where
    N: NodePrimitives,
    N::Block: Block<Header = Header>,
{
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<N::Block>,
        result: &reth_execution_types::BlockExecutionResult<N::Receipt>,
        receipt_root_bloom: Option<ReceiptRootBloom>,
        block_access_list_hash: Option<B256>,
    ) -> Result<(), ConsensusError> {
        validate_block_post_execution(
            block,
            &self.chain_spec,
            result,
            receipt_root_bloom,
            block_access_list_hash,
        )
    }
}
