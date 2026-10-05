//! Clique `PoA` node built on reth's node-builder.
//!
//! [`CliqueNode`] is an Ethereum node with two swapped components: the
//! consensus ([`CliqueConsensus`] — clique rules) and the EVM executor
//! ([`CliqueEvmConfig`] — vanilla execution without `PoW` block rewards,
//! which geth's clique engine never pays). Everything else (pool, payload
//! builder, network, RPC) is the standard reth Ethereum stack. Sync is
//! driven by [`follower::CliqueFollower`] (tempo-style `--follow` over RPC)
//! while block data flows over normal devp2p.

pub mod engine_validator;
pub mod evm;
pub mod follower;
pub mod node;
pub mod parser;
pub mod payload;
pub mod rpc;
pub mod signer;

pub use engine_validator::{CliqueEngineValidator, CliqueEngineValidatorBuilder};
pub use evm::{CliqueEvmConfig, CliqueExecutorBuilder, NoRewardSpec};
pub use follower::{CliqueFollower, CliqueFollowerConfig, FollowStatus, connect_upstream};
pub use node::{built_consensus, first_consensus, CliqueAddOns, CliqueConsensusBuilder, CliqueNode, ProviderHeaderSource};
pub use parser::{CliqueChainSpecParser, CliqueCliExt};
pub use payload::{CliqueEngineTypes, CliqueExecutionData};
pub use rpc::{CliqueApiImpl, CliqueApiServer};
pub use signer::{CliqueMinerState, CliqueSignerService};
