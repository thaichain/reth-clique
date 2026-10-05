//! Clique block sealer — turns reth into a clique validator.
//!
//! Mirrors geth's clique `Prepare`/`Seal` flow on top of reth's engine:
//! 1. wait for the next clique slot (`parent.timestamp + period`),
//! 2. check the vote snapshot: authorized signer, not in the recents window,
//! 3. build the block body via reth's payload builder (execution included),
//! 4. restamp the header with clique fields (difficulty 1/2, extraData with
//!    signers on checkpoints, vote coinbase/nonce) and sign the seal hash,
//! 5. submit via `new_payload` + `fork_choice_updated`.

use crate::follower::ConsensusEngineHandleApi;
use alloy_consensus::Header;
use alloy_primitives::{Address, B256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use clique_consensus::{seal::seal_hash, CliqueConsensus, EXTRA_SEAL};
use alloy_rpc_types_engine::ForkchoiceState;
use reth_engine_primitives::ConsensusEngineHandle;
use reth_ethereum::{provider::BlockNumReader, provider::HeaderProvider, Block};
use reth_ethereum::primitives::SealedBlock;
use crate::payload::{CliqueEngineTypes, CliqueExecutionData};
use reth_payload_builder::PayloadBuilderHandle;
use reth_payload_primitives::PayloadKind;
use reth_primitives_traits::SealedHeader;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex as AsyncMutex;

/// Shared miner state: the signer identity and the current vote proposals
/// (geth's `proposals` map, driven by `clique_propose`/`clique_discard`).
#[derive(Debug)]
pub struct CliqueMinerState {
    /// The signer address (derived from the private key).
    pub signer: Address,
    /// 32-byte extraData vanity prefix.
    pub vanity: [u8; 32],
    /// address -> authorize? (clique proposals)
    pub proposals: Mutex<HashMap<Address, bool>>,
}

impl CliqueMinerState {
    /// Creates the miner state with a zero vanity.
    pub fn new(signer: Address) -> Self {
        Self { signer, vanity: [0u8; 32], proposals: Mutex::new(HashMap::new()) }
    }
}

/// The clique block sealer.
#[derive(derive_more::Debug)]
pub struct CliqueSignerService<P> {
    engine: ConsensusEngineHandle<CliqueEngineTypes>,
    payload_builder: PayloadBuilderHandle<CliqueEngineTypes>,
    consensus: Arc<CliqueConsensus>,
    state: Arc<CliqueMinerState>,
    signer: PrivateKeySigner,
    #[debug(ignore)]
    provider: P,
    poll_interval: Duration,
    /// Hash of the last parent we sealed on (avoid double-sealing one parent).
    last_sealed_parent: AsyncMutex<B256>,
}

impl<P> CliqueSignerService<P>
where
    P: BlockNumReader + HeaderProvider<Header = Header> + Clone + Send + Sync + 'static,
{
    /// Creates the sealer.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        engine: ConsensusEngineHandle<CliqueEngineTypes>,
        payload_builder: PayloadBuilderHandle<CliqueEngineTypes>,
        consensus: Arc<CliqueConsensus>,
        state: Arc<CliqueMinerState>,
        signer: PrivateKeySigner,
        provider: P,
    ) -> Self {
        Self {
            engine,
            payload_builder,
            consensus,
            state,
            signer,
            provider,
            poll_interval: Duration::from_millis(250),
            last_sealed_parent: AsyncMutex::new(B256::ZERO),
        }
    }

    /// Runs the sealing loop until the task is cancelled.
    pub async fn run(self) {
        loop {
            tokio::time::sleep(self.poll_interval).await;
            if let Err(err) = self.try_seal().await {
                tracing::debug!(target: "clique::sealer", %err, "seal attempt skipped");
            }
        }
    }

    /// One sealing attempt for the current head.
    async fn try_seal(&self) -> eyre::Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let parent_number = self.provider.best_block_number()?;
        let parent_header = self
            .provider
            .header_by_number(parent_number)?
            .ok_or_else(|| eyre::eyre!("head header missing"))?;
        let parent = SealedHeader::seal_slow(parent_header);

        // one seal per parent
        {
            let last = self.last_sealed_parent.lock().await;
            if *last == parent.hash() {
                return Err(eyre::eyre!("already sealed on this parent"));
            }
        }

        let config = self.consensus.config();
        let period = config.period_at(parent.timestamp);
        let slot_time = parent.timestamp + period;
        if now < slot_time {
            return Err(eyre::eyre!("too early for next slot"));
        }
        let block_time = slot_time.max(now);

        let snap = self.consensus.snapshot_for(parent_number, parent.hash())?;
        let signer_addr = self.state.signer;
        if !snap.signers.contains(&signer_addr) {
            return Err(eyre::eyre!("not an authorized signer"));
        }
        // recents protection (geth Seal): a signer may sign at most one of
        // any floor(N/2)+1 consecutive blocks. Note: `number` here is the NEW
        // block number, matching geth's Seal which receives the fresh header.
        let number = parent_number + 1;
        let limit = snap.signers.len() as u64 / 2 + 1;
        for (seen, recent) in &snap.recents {
            if *recent == signer_addr && number >= limit && *seen > number - limit {
                return Err(eyre::eyre!("signed recently, must wait for others"));
            }
        }

        let inturn = snap.inturn(parent_number + 1, signer_addr);
        if !inturn {
            // out-of-turn: add a random wiggle so the in-turn signer wins
            // races. Scaled to the period so short slots stay usable
            // (500ms is 1/20th of the legacy 10s period).
            let wiggle_ms = (snap.signers.len() as u64 / 2 + 1) * period * 50;
            let since_slot_ms = (now - slot_time) * 1000;
            if since_slot_ms < wiggle_ms {
                return Err(eyre::eyre!("out-of-turn, waiting for wiggle"));
            }
        }

        // pick a vote (geth samples a random valid proposal; first is fine)
        let (vote_target, vote_nonce) = {
            let proposals = self.state.proposals.lock().unwrap();
            let valid: Vec<(&Address, &bool)> = proposals
                .iter()
                .filter(|(addr, auth)| snap.valid_vote(**addr, **auth))
                .collect();
            match valid.first() {
                Some((addr, auth)) => (
                    **addr,
                    if **auth {
                        clique_consensus::NONCE_AUTH_VOTE
                    } else {
                        clique_consensus::NONCE_DROP_VOTE
                    },
                ),
                None => (Address::ZERO, clique_consensus::NONCE_DROP_VOTE),
            }
        };

        // checkpoint blocks carry the full signer list and no vote
        let checkpoint = config.is_checkpoint(parent_number + 1);
        let (vote_target, vote_nonce) = if checkpoint {
            (Address::ZERO, clique_consensus::NONCE_DROP_VOTE)
        } else {
            (vote_target, vote_nonce)
        };

        let tempo_form = self.consensus.is_tempo_form(block_time);
        let difficulty = if tempo_form {
            alloy_primitives::U256::ZERO
        } else if inturn {
            clique_consensus::DIFF_INTURN
        } else {
            clique_consensus::DIFF_NOTURN
        };

        // 1. trigger payload building on top of the parent head
        let attrs = reth_ethereum_engine_primitives::EthPayloadAttributes {
            timestamp: block_time,
            suggested_fee_recipient: vote_target,
            prev_randao: B256::ZERO,
            withdrawals: tempo_form.then(Vec::new),
            parent_beacon_block_root: tempo_form.then_some(B256::ZERO),
            slot_number: None,
            target_gas_limit: None,
        };
        let state = ForkchoiceState {
            head_block_hash: parent.hash(),
            safe_block_hash: B256::ZERO,
            finalized_block_hash: B256::ZERO,
        };
        let updated = self
            .engine
            .fork_choice_update(state, Some(attrs))
            .await
            .map_err(|e| eyre::eyre!("fcu for payload job: {e}"))?;
        let payload_id =
            updated.payload_id.ok_or_else(|| eyre::eyre!("no payload id returned"))?;

        // 2. resolve the built payload (execution included)
        let built = self
            .payload_builder
            .resolve_kind(payload_id, PayloadKind::WaitForPending)
            .await
            .ok_or_else(|| eyre::eyre!("payload not found"))?
            .map_err(|e| eyre::eyre!("payload build failed: {e}"))?;

        // 3. restamp the header with clique fields and sign.
        // Tempo form (post pragueTime): keep the vanilla post-merge fields the
        // builder emitted (withdrawals root, beacon root, blob gas, requests
        // hash) and zero out the clique fields.
        // Clique form (pre-boundary): strip back to clique form — the vanilla
        // builder emits Shanghai/Cancun/Prague fields which don't exist in
        // clique blocks.
        let mut block: Block = built.block().clone().into_block();
        let mut header: Header = block.header.clone();
        header.difficulty = difficulty;
        header.nonce = vote_nonce;
        header.beneficiary = vote_target;
        header.mix_hash = B256::ZERO;
        header.timestamp = block_time;
        if tempo_form {
            block.body.withdrawals = Some(Vec::new().into());
            header.withdrawals_root = Some(alloy_consensus::constants::EMPTY_WITHDRAWALS);
            header.parent_beacon_block_root = Some(B256::ZERO);
            header.blob_gas_used = Some(0);
            header.excess_blob_gas = Some(0);
        } else {
            block.body.withdrawals = None;
            header.withdrawals_root = None;
            header.blob_gas_used = None;
            header.excess_blob_gas = None;
            header.parent_beacon_block_root = None;
            header.requests_hash = None;
        }

        let mut extra: Vec<u8> = self.state.vanity.to_vec();
        if checkpoint && !tempo_form {
            for signer in snap.signers_sorted() {
                extra.extend_from_slice(signer.as_slice());
            }
        }
        extra.extend_from_slice(&[0u8; EXTRA_SEAL]);
        header.extra_data = extra.into();

        // sign keccak(rlp(header minus seal tail)) and copy into the tail
        let sighash = seal_hash(&header);
        let sig = self.signer.sign_hash_sync(&sighash)?;
        let sig65 = sig.as_rsy(); // v ∈ {0,1}, geth clique convention
        let mut extra = header.extra_data.to_vec();
        let len = extra.len();
        extra[len - EXTRA_SEAL..].copy_from_slice(&sig65);
        header.extra_data = extra.into();

        let sealed = SealedBlock::seal_slow(Block { header, body: block.body });

        // 4. submit and make canonical
        self.engine.submit_payload(CliqueExecutionData { block: sealed.clone() }).await?;
        {
            let mut last = self.last_sealed_parent.lock().await;
            *last = parent.hash();
        }
        let fcu = ForkchoiceState {
            head_block_hash: sealed.hash(),
            safe_block_hash: B256::ZERO,
            finalized_block_hash: B256::ZERO,
        };
        self.engine.fork_choice_update(fcu, None).await?;

        tracing::info!(
            target: "clique::sealer",
            number = sealed.number,
            hash = %sealed.hash(),
            inturn,
            "sealed clique block"
        );
        Ok(())
    }
}
