//! `clique_*` RPC namespace — a port of geth's clique API on top of
//! [`CliqueConsensus`] and [`CliqueMinerState`].
//!
//! Provided: `getSnapshot`, `getSnapshotAtHash`, `getSigners`,
//! `getSignersAtHash`, `proposals`, `propose`, `discard`, `status`.
//! (`getSignersAtHash` resolves snapshots through ancestor replay from the
//! closest snapshot point, same as geth.)

use crate::signer::CliqueMinerState;
use alloy_primitives::{Address, B256};
use clique_consensus::{CliqueConsensus, Snapshot};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_ethereum::provider::{BlockNumReader, HeaderProvider};
use reth_rpc_server_types::ToRpcResult;
use std::{collections::BTreeMap, sync::Arc};

/// Converts any displayable error into an `rpc` `ErrorObject`.
fn rpc_err(e: impl std::fmt::Display) -> jsonrpsee::types::ErrorObject<'static> {
    jsonrpsee::types::ErrorObject::owned(
        jsonrpsee::types::error::CALL_EXECUTION_FAILED_CODE,
        e.to_string(),
        None::<()>,
    )
}

/// Serializable snapshot for RPC output (geth's `Snapshot` JSON shape).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotJson {
    /// Block number the snapshot was taken at.
    pub number: u64,
    /// Block hash the snapshot was taken at.
    pub hash: B256,
    /// Ordered authorized signer addresses.
    pub signers: BTreeMap<Address, serde_json::Value>,
    /// Recently signed blocks per signer (signer -> last block number).
    pub recents: BTreeMap<u64, Address>,
    /// Votes currently pending tally.
    pub votes: Vec<VoteJson>,
    /// Current vote tally per target address.
    pub tally: BTreeMap<Address, TallyJson>,
}

/// A single cast vote (geth's `Vote` JSON shape).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VoteJson {
    /// Address of the signer that cast the vote.
    pub signer: Address,
    /// Block number the vote was cast in.
    pub block: u64,
    /// Address the vote targets.
    pub address: Address,
    /// `true` to authorize the target, `false` to deauthorize.
    pub authorize: bool,
}

/// Aggregate votes for one target address (geth's `Tally` JSON shape).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TallyJson {
    /// `true` if the votes authorize the target.
    pub authorize: bool,
    /// Number of votes counted toward the target.
    pub votes: usize,
}

fn snapshot_to_json(snap: &Snapshot) -> SnapshotJson {
    SnapshotJson {
        number: snap.number,
        hash: snap.hash,
        signers: snap
            .signers
            .iter()
            .map(|a| (*a, serde_json::Value::Object(Default::default())))
            .collect(),
        recents: snap.recents.iter().map(|(k, v)| (*k, *v)).collect(),
        votes: snap
            .votes
            .iter()
            .map(|v| VoteJson {
                signer: v.signer,
                block: v.block,
                address: v.address,
                authorize: v.authorize,
            })
            .collect(),
        tally: snap
            .tally
            .iter()
            .map(|(a, t)| {
                (
                    *a,
                    TallyJson { authorize: t.authorize, votes: t.votes },
                )
            })
            .collect(),
    }
}

/// Per-signer sealing statistics over the last 64 blocks (geth's `status`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusJson {
    /// Percentage of recent blocks sealed in-turn.
    pub in_turn_percent: u64,
    /// Blocks sealed per signer address, as hex strings.
    pub signing_status: BTreeMap<String, u64>,
    /// Number of recent blocks the statistics cover.
    pub num_blocks: u64,
}

/// trait interface for the `clique` namespace.
#[cfg_attr(not(test), rpc(server, namespace = "clique"))]
#[cfg_attr(test, rpc(server, client, namespace = "clique"))]
pub trait CliqueApi {
    /// Returns the vote snapshot at the current head.
    #[method(name = "getSnapshot")]
    fn get_snapshot(&self) -> RpcResult<SnapshotJson>;

    /// Returns the vote snapshot at the given block hash.
    #[method(name = "getSnapshotAtHash")]
    fn get_snapshot_at_hash(&self, hash: B256) -> RpcResult<SnapshotJson>;

    /// Returns the authorized signers at the current head.
    #[method(name = "getSigners")]
    fn get_signers(&self) -> RpcResult<Vec<Address>>;

    /// Returns the authorized signers at the given block hash.
    #[method(name = "getSignersAtHash")]
    fn get_signers_at_hash(&self, hash: B256) -> RpcResult<Vec<Address>>;

    /// Returns the current proposals made by this node.
    #[method(name = "proposals")]
    fn proposals(&self) -> RpcResult<BTreeMap<Address, bool>>;

    /// Adds a proposal to vote the address in or out at the next checkpoint.
    #[method(name = "propose")]
    fn propose(&self, address: Address, authorize: bool) -> RpcResult<()>;

    /// Drops all outstanding proposals for the given address.
    #[method(name = "discard")]
    fn discard(&self, address: Address) -> RpcResult<()>;

    /// Returns sealing statistics for recent blocks.
    #[method(name = "status")]
    fn status(&self) -> RpcResult<StatusJson>;
}

/// The clique RPC implementation.
#[derive(derive_more::Debug)]
pub struct CliqueApiImpl<P> {
    consensus: Arc<CliqueConsensus>,
    miner: Arc<CliqueMinerState>,
    #[debug(ignore)]
    provider: P,
}

impl<P> CliqueApiImpl<P>
where
    P: BlockNumReader + HeaderProvider<Header = alloy_consensus::Header> + Send + Sync + 'static,
{
    /// Resolves the vote snapshot at a (number, hash) point.
    pub fn snapshot_at(&self, number: u64, hash: B256) -> RpcResult<Snapshot> {
        self.consensus
            .snapshot_for(number, hash)
            .map(|snap| (*snap).clone())
            .map_err(rpc_err)
    }
}

impl<P> CliqueApiServer for CliqueApiImpl<P>
where
    P: BlockNumReader + HeaderProvider<Header = alloy_consensus::Header> + Send + Sync + 'static,
{
    fn get_snapshot(&self) -> RpcResult<SnapshotJson> {
        let number = self.provider.best_block_number().to_rpc_result()?;
        let hash = self
            .provider
            .block_hash(number)
            .to_rpc_result()?
            .ok_or_else(|| rpc_err("head hash missing"))?;
        Ok(snapshot_to_json(&self.snapshot_at(number, hash)?))
    }

    fn get_snapshot_at_hash(&self, hash: B256) -> RpcResult<SnapshotJson> {
        let header = self
            .provider
            .header(hash)
            .to_rpc_result()?
            .ok_or_else(|| rpc_err("header not found"))?;
        Ok(snapshot_to_json(&self.snapshot_at(header.number, hash)?))
    }

    fn get_signers(&self) -> RpcResult<Vec<Address>> {
        Ok(self.get_snapshot()?.signers.into_keys().collect())
    }

    fn get_signers_at_hash(&self, hash: B256) -> RpcResult<Vec<Address>> {
        Ok(self.get_snapshot_at_hash(hash)?.signers.into_keys().collect())
    }

    fn proposals(&self) -> RpcResult<BTreeMap<Address, bool>> {
        Ok(self.miner.proposals.lock().unwrap().clone().into_iter().collect())
    }

    fn propose(&self, address: Address, authorize: bool) -> RpcResult<()> {
        self.miner.proposals.lock().unwrap().insert(address, authorize);
        Ok(())
    }

    fn discard(&self, address: Address) -> RpcResult<()> {
        self.miner.proposals.lock().unwrap().remove(&address);
        Ok(())
    }

    fn status(&self) -> RpcResult<StatusJson> {
        let number = self.provider.best_block_number().to_rpc_result()?;
        let start = number.saturating_sub(64);
        let mut signers: BTreeMap<Address, u64> = BTreeMap::new();
        let mut inturn = 0u64;
        let mut num_blocks = 0u64;
        let mut snap = self.snapshot_at(
            start,
            self.provider
                .block_hash(start)
                .to_rpc_result()?
                .ok_or_else(|| rpc_err("header not found"))?,
        )?;
        for n in (start + 1)..=number {
            let header = self
                .provider
                .header_by_number(n)
                .to_rpc_result()?
                .ok_or_else(|| rpc_err("header not found"))?;
            let signer = snap
                .verify_seal(&header, n)
                .map_err(|e| jsonrpsee::types::ErrorObject::owned(
                    jsonrpsee::types::error::CALL_EXECUTION_FAILED_CODE,
                    e.to_string(),
                    None::<()>,
                ))?;
            if snap.inturn(n, signer) {
                inturn += 1;
            }
            *signers.entry(signer).or_default() += 1;
            num_blocks += 1;
            // advance the snapshot across this header
            let sealed = reth_primitives_traits::SealedHeader::seal_slow(header);
            snap = snap
                .apply(
                    std::slice::from_ref(&sealed),
                    clique_consensus::seal::recover_signer,
                )
                .map_err(|e| jsonrpsee::types::ErrorObject::owned(
                    jsonrpsee::types::error::CALL_EXECUTION_FAILED_CODE,
                    e.to_string(),
                    None::<()>,
                ))?;
        }
        Ok(StatusJson {
            in_turn_percent: inturn.checked_mul(100).and_then(|v| v.checked_div(num_blocks)).unwrap_or(0),
            signing_status: signers
                .into_iter()
                .map(|(a, c)| (format!("{a:?}"), c))
                .collect(),
            num_blocks,
        })
    }
}

impl<P> CliqueApiImpl<P> {
    /// Creates the API with the given node provider.
    pub const fn new(
        consensus: Arc<CliqueConsensus>,
        miner: Arc<CliqueMinerState>,
        provider: P,
    ) -> Self {
        Self { consensus, miner, provider }
    }
}
