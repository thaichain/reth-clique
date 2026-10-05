//! `clique-reth` — a reth-based Clique `PoA` node.
//!
//! ```sh
//! # sync follower of an existing clique chain (tempo-style follow mode)
//! clique-reth node \
//!   --chain ./genesis.json \
//!   --datadir ./data \
//!   --follow http://<upstream>:8545 \
//!   --http
//!
//! # act as a clique validator (seal blocks)
//! clique-reth node \
//!   --chain ./genesis.json \
//!   --datadir ./data \
//!   --follow http://<upstream>:8545 \
//!   --miner.key 0x... \
//!   --http
//! ```

use clique_node::{
    built_consensus, connect_upstream, CliqueApiImpl, CliqueApiServer, CliqueChainSpecParser,
    CliqueCliExt, CliqueFollower, CliqueMinerState, CliqueNode, CliqueSignerService,
    ProviderHeaderSource,
};
use clap::Parser as _;
use reth_ethereum::cli::interface::Cli;
use reth_ethereum::provider::CanonStateSubscriptions;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn main() {
    Cli::<CliqueChainSpecParser, CliqueCliExt>::parse()
        .run(async move |builder, args| {
            // Shared miner state (signer identity + vote proposals). The RPC
            // namespace and the sealer both mutate/read it.
            let miner_state = match &args.miner_key {
                Some(key) => {
                    let signer = alloy_signer_local::PrivateKeySigner::from_bytes(key)?;
                    Arc::new(CliqueMinerState::new(signer.address()))
                }
                None => Arc::new(CliqueMinerState::new(Default::default())),
            };

            let node_builder = builder.node(CliqueNode).extend_rpc_modules({
                let miner_state = miner_state.clone();
                move |ctx| {
                // Runs during launch (after components are built), so the
                // consensus registry is already populated.
                let consensus = clique_node::first_consensus()
                    .ok_or_else(|| eyre::eyre!("consensus missing from registry"))?;
                let provider = ctx.registry.eth_api().provider().clone();
                let api = CliqueApiImpl::new(consensus, miner_state, provider);
                ctx.modules.merge_configured(api.into_rpc())?;
                tracing::info!(target: "clique::rpc", "clique_* namespace enabled");
                Ok(())
            }});

            let reth_ethereum::node::builder::NodeHandle { node, node_exit_future } =
                node_builder.launch_with_debug_capabilities().await?;

            // Feed local headers into the clique consensus so vote snapshots
            // can be reconstructed from the database.
            let chain_id = node.config.chain.chain().id();
            let consensus = built_consensus(chain_id)
                .ok_or_else(|| eyre::eyre!("consensus engine missing from registry"))?;
            consensus
                .set_header_source(Arc::new(ProviderHeaderSource::new(node.provider.clone())));

            // Tempo-style follow mode: catch up missing blocks + track the
            // upstream head via in-process engine calls; all blocks are
            // executed and validated locally.
            if let (Some(url), Some(config)) = (&args.follow, args.follower_config()) {
                tracing::info!(target: "clique::follower", %url, "starting follow mode");
                let upstream = connect_upstream(url).await?;
                let engine = node.add_ons_handle.beacon_engine_handle.clone();

                // Track the engine's canonical head, including in-memory tree
                // blocks: the DB-backed provider number lags until the tree
                // persists, which would make the follower re-request (and
                // re-reject) already-imported upstream blocks.
                let head = Arc::new(AtomicU64::new(
                    reth_ethereum::provider::BlockNumReader::last_block_number(&node.provider)
                        .unwrap_or(0),
                ));
                let head_tracker = head.clone();
                let provider = node.provider.clone();
                node.task_executor.spawn_critical_task("clique_head_tracker", async move {
                    let mut rx = provider.subscribe_to_canonical_state();
                    loop {
                        match rx.recv().await {
                            Ok(notif) => {
                                head_tracker.store(notif.tip().number, Ordering::Relaxed)
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                            Err(_) => break,
                        }
                    }
                });
                let local_head = Box::new(move || head.load(Ordering::Relaxed));
                let follower = CliqueFollower::new(engine, upstream, config, local_head);
                node.task_executor
                    .spawn_critical_task("clique_follower", async move { follower.run().await });
            }

            // Validator mode: seal blocks with the given key.
            if let Some(key) = &args.miner_key {
                let signer = alloy_signer_local::PrivateKeySigner::from_bytes(key)?;
                let sealer = CliqueSignerService::new(
                    node.add_ons_handle.beacon_engine_handle.clone(),
                    node.payload_builder_handle.clone(),
                    consensus.clone(),
                    miner_state.clone(),
                    signer,
                    node.provider.clone(),
                );
                node.task_executor
                    .spawn_critical_task("clique_sealer", async move { sealer.run().await });
            }

            node_exit_future.await
        })
        .unwrap();
}
