//! CLI integration: the clique chain spec parser and follow-mode CLI args.

use clique_chainspec::load_clique_chainspec;
use reth_cli::chainspec::ChainSpecParser;
use reth_ethereum::chainspec::ChainSpec;
use std::{sync::Arc, time::Duration};

/// Chain spec parser that loads a clique genesis.json (`--chain ./genesis.json`).
///
/// Parsing registers the clique config (`period`/`epoch`) for the chain id so
/// that [`crate::node::CliqueConsensusBuilder`] can pick it up.
#[derive(Debug, Clone, Copy, Default)]
pub struct CliqueChainSpecParser;

impl ChainSpecParser for CliqueChainSpecParser {
    type ChainSpec = ChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = &[];

    fn parse(s: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
        // Accept a path to a genesis file or an inline JSON document
        let json = if s.trim_start().starts_with('{') {
            s.to_string()
        } else {
            std::fs::read_to_string(s)
                .map_err(|err| eyre::eyre!("failed to read chain spec file {s:?}: {err}"))?
        };
        let spec = load_clique_chainspec(&json)?;
        tracing::info!(
            target: "clique::chainspec",
            chain_id = spec.chain().id(),
            period = spec.clique.period,
            epoch = spec.clique.epoch,
            "loaded clique chain spec"
        );
        clique_chainspec::register_clique_config(spec.chain().id(), spec.clique);
        Ok(spec.inner)
    }
}

/// Additional CLI args for the clique node.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct CliqueCliExt {
    /// Follow an upstream node's head over RPC and drive local sync
    /// (tempo-style follow mode). Accepts http(s):// or ws(s):// URLs.
    #[arg(long = "follow", value_name = "URL")]
    pub follow: Option<String>,

    /// Poll interval for follow mode, in milliseconds.
    #[arg(long = "follow-poll-ms", value_name = "MS", default_value_t = 1000)]
    pub follow_poll_ms: u64,

    /// Private key used to seal clique blocks (validator mode). When set, the
    /// node seals blocks whenever it is authorized and in turn.
    #[arg(long = "miner.key", value_name = "KEY")]
    pub miner_key: Option<alloy_primitives::B256>,
}

impl CliqueCliExt {
    /// Returns the follower config if `--follow` is set.
    pub fn follower_config(&self) -> Option<CliqueFollowerConfig> {
        self.follow
            .as_ref()
            .map(|_| CliqueFollowerConfig::new(Duration::from_millis(self.follow_poll_ms)))
    }
}

use crate::follower::CliqueFollowerConfig;
