//! Follow-mode sync driver — the tempo-style follower stack.
//!
//! [`CliqueFollower`] polls an upstream node's RPC (`--follow http(s)://…` or
//! `ws(s)://…`) and drives the local reth engine:
//! 1. **History catch-up**: any missing blocks between the local head and the
//!    upstream head are fetched over RPC and submitted via `new_payload`
//!    (useful when devp2p peers are unavailable or still forming).
//! 2. **Head tracking**: `fork_choice_updated` keeps the engine pointed at the
//!    upstream head; block data may still flow over normal devp2p.
//!
//! Every block is still fully validated locally by
//! [`CliqueConsensus`](clique_consensus::CliqueConsensus) during execution —
//! the upstream is only a sync hint.

use alloy_eips::BlockId;
use alloy_primitives::B256;
use alloy_provider::Provider;
use alloy_rpc_types_engine::{ForkchoiceState, ForkchoiceUpdated, PayloadStatusEnum};
use reth_engine_primitives::{
    BeaconForkChoiceUpdateError, BeaconOnNewPayloadError, ConsensusEngineHandle, EngineTypes,
};
use reth_ethereum::Block;
use crate::payload::CliqueEngineTypes;
use reth_payload_primitives::PayloadTypes as _;
use reth_ethereum::primitives::SealedBlock;
use std::{future::Future, time::Duration};
use tokio::time::sleep;

/// Configuration for [`CliqueFollower`].
#[derive(Debug, Clone)]
pub struct CliqueFollowerConfig {
    /// Poll interval for the upstream head.
    pub poll_interval: Duration,
    /// How many blocks ahead of the local head to prefetch over RPC when far
    /// behind (burst catch-up). Prefetch is concurrent; submission stays in
    /// order.
    pub prefetch_window: u64,
    /// Max in-flight RPC requests during prefetch.
    pub prefetch_concurrency: usize,
}

impl CliqueFollowerConfig {
    /// Creates the config with the given poll interval and default prefetch settings.
    pub const fn new(poll_interval: Duration) -> Self {
        Self { poll_interval, prefetch_window: 512, prefetch_concurrency: 48 }
    }
}

/// Outcome of one follow iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowStatus {
    /// The engine accepted the head as canonical.
    Accepted,
    /// The engine is downloading/executing towards the head.
    Syncing,
    /// The engine rejected the head (consensus violation).
    Rejected,
}

/// Converts an RPC block into clique execution data.
pub fn rpc_block_to_payload(
    rpc_block: alloy_rpc_types_eth::Block,
) -> crate::payload::CliqueExecutionData {
    let block: Block = rpc_block.into_consensus().convert_transactions();
    CliqueEngineTypes::block_to_payload(SealedBlock::new_unhashed(block), None)
}

/// Drives the local engine to follow an upstream node's head.
pub struct CliqueFollower<Engine, Upstream> {
    engine: Engine,
    upstream: Upstream,
    config: CliqueFollowerConfig,
    local_head: Box<dyn Fn() -> u64 + Send + Sync>,
    last_followed: Option<(u64, B256)>,
}

impl<Engine, Upstream> core::fmt::Debug for CliqueFollower<Engine, Upstream> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CliqueFollower").field("config", &self.config).finish_non_exhaustive()
    }
}

impl<Engine, Upstream> CliqueFollower<Engine, Upstream>
where
    Engine: ConsensusEngineHandleApi,
    Upstream: Provider,
{
    /// `local_head` returns the current local canonical block number.
    pub fn new(
        engine: Engine,
        upstream: Upstream,
        config: CliqueFollowerConfig,
        local_head: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self { engine, upstream, config, local_head, last_followed: None }
    }

    /// Runs the follow loop until the task is cancelled.
    pub async fn run(mut self) {
        loop {
            sleep(self.config.poll_interval).await;
            match self.poll_once().await {
                Ok(Some(FollowStatus::Syncing)) => {
                    tracing::debug!(target: "clique::follower", "engine syncing towards upstream head");
                }
                Ok(Some(FollowStatus::Rejected)) => {
                    tracing::warn!(
                        target: "clique::follower",
                        "upstream head rejected by local consensus — check genesis/hardfork match"
                    );
                }
                Ok(_) => {}
                Err(err) => {
                    tracing::warn!(target: "clique::follower", %err, "follow poll failed");
                }
            }
        }
    }

    /// One follow iteration: catch up missing blocks over RPC, then push a
    /// fork choice update to the engine.
    async fn poll_once(&mut self) -> eyre::Result<Option<FollowStatus>> {
        let head_block =
            self.upstream.get_block(BlockId::latest()).await?.ok_or_else(|| {
                eyre::eyre!("upstream returned no latest block")
            })?;
        let number = head_block.header.number;
        let hash = head_block.header.hash;

        let mut local = (self.local_head)();

        // Upstream is behind our own canonical head (e.g. the pre-takeover
        // validator frozen at the hardfork boundary while the local sealer
        // continues past it): following the older head would reorg away
        // locally sealed blocks, or spin on `Syncing` for a block the engine
        // already rejected. Skip until upstream advances.
        if number < local {
            return Ok(None);
        }

        // History catch-up: fetch and submit every missing block in order.
        // Single-validator clique chains produce empty blocks, so this loop
        // is short even after downtime.
        while local < number {
            let next = local + 1;
            let block = self
                .upstream
                .get_block(BlockId::Number(next.into()))
                .await?
                .ok_or_else(|| eyre::eyre!("upstream missing block {next}"))?;
            let block_hash = block.header.hash;
            let payload = rpc_block_to_payload(block);
            let status = self.engine.submit_payload(payload).await?;
            match status.status {
                PayloadStatusEnum::Valid | PayloadStatusEnum::Accepted => {
                    // make each block canonical immediately: the consensus
                    // snapshot walk reads recent blocks through the provider,
                    // which only sees canonical (FCU'd) blocks
                    let fcu = ForkchoiceState {
                        head_block_hash: block_hash,
                        safe_block_hash: B256::ZERO,
                        finalized_block_hash: B256::ZERO,
                    };
                    let _: ForkchoiceUpdated = self.engine.fork_choice_update(fcu, None).await?;
                    local = next;
                }
                PayloadStatusEnum::Syncing => {
                    tracing::debug!(target: "clique::follower", %next, "engine syncing during catch-up");
                    break;
                }
                PayloadStatusEnum::Invalid { .. } => {
                    tracing::error!(
                        target: "clique::follower", %next,
                        "block from upstream is invalid according to local consensus"
                    );
                    return Ok(Some(FollowStatus::Rejected));
                }
            }
        }

        if self.last_followed == Some((number, hash)) {
            return Ok(None);
        }

        tracing::info!(target: "clique::follower", %number, %hash, "following upstream head");
        let state = ForkchoiceState {
            head_block_hash: hash,
            safe_block_hash: B256::ZERO,
            finalized_block_hash: B256::ZERO,
        };
        let updated: ForkchoiceUpdated = self
            .engine
            .fork_choice_update(state, None::<alloy_rpc_types_engine::PayloadAttributes>)
            .await?;
        match updated.payload_status.status {
            PayloadStatusEnum::Syncing => {
                Ok(Some(FollowStatus::Syncing))
            }
            PayloadStatusEnum::Invalid { .. } => {
                tracing::warn!(
                    target: "clique::follower", %number, %hash,
                    "upstream head invalid according to local consensus"
                );
                self.last_followed = Some((number, hash));
                Ok(Some(FollowStatus::Rejected))
            }
            _ => {
                self.last_followed = Some((number, hash));
                Ok(Some(FollowStatus::Accepted))
            }
        }
    }
}

/// The subset of [`ConsensusEngineHandle`] the follower needs.
pub trait ConsensusEngineHandleApi: Send + Sync + 'static {
    /// Forwards a fork choice update to the engine.
    fn fork_choice_update(
        &self,
        state: ForkchoiceState,
        attrs: Option<alloy_rpc_types_engine::PayloadAttributes>,
    ) -> impl Future<Output = Result<ForkchoiceUpdated, BeaconForkChoiceUpdateError>> + Send;

    /// Submits an execution payload to the engine via `new_payload`.
    fn submit_payload(
        &self,
        payload: crate::payload::CliqueExecutionData,
    ) -> impl Future<Output = Result<alloy_rpc_types_engine::PayloadStatus, BeaconOnNewPayloadError>>
    + Send;
}

impl<ET> ConsensusEngineHandleApi for ConsensusEngineHandle<ET>
where
    ET: EngineTypes<
        ExecutionData = crate::payload::CliqueExecutionData,
        PayloadAttributes = alloy_rpc_types_engine::PayloadAttributes,
    >,
{
    fn fork_choice_update(
        &self,
        state: ForkchoiceState,
        attrs: Option<alloy_rpc_types_engine::PayloadAttributes>,
    ) -> impl Future<Output = Result<ForkchoiceUpdated, BeaconForkChoiceUpdateError>> + Send {
        Self::fork_choice_updated(self, state, attrs)
    }

    fn submit_payload(
        &self,
        payload: crate::payload::CliqueExecutionData,
    ) -> impl Future<Output = Result<alloy_rpc_types_engine::PayloadStatus, BeaconOnNewPayloadError>>
    + Send {
        Self::new_payload(self, payload)
    }
}

/// Connects to the upstream node over http(s) or ws(s) (transport
/// auto-detected from the URL scheme).
pub async fn connect_upstream(url: &str) -> eyre::Result<impl Provider> {
    Ok(alloy_provider::ProviderBuilder::new().connect(url).await?)
}
