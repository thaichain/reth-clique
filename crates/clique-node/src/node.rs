//! [`CliqueNode`] — a reth Ethereum node with clique consensus.

use crate::engine_validator::CliqueEngineValidatorBuilder;
use crate::evm::CliqueExecutorBuilder;
use crate::payload::CliqueEngineTypes;
use alloy_consensus::Header;
use alloy_primitives::B256;
use clique_chainspec::registered_clique_config;
use clique_consensus::CliqueConsensus;
use reth_ethereum::{
    chainspec::ChainSpec,
    node::{
        api::{node::FullNodeTypes, payload::PayloadTypes, NodeTypes},
        builder::{
            components::{BasicPayloadServiceBuilder, ComponentsBuilder, ConsensusBuilder},
            rpc::{
                BasicEngineValidatorBuilder, Identity, NoopEngineApiBuilder,
                RpcAddOns,
            }, BuilderContext, DebugNode, Node, NodeAdapter,
        },
        EthereumEthApiBuilder, EthereumNetworkBuilder, EthereumPayloadBuilder,
        EthereumPoolBuilder,
    },
    provider::HeaderProvider,
    storage::EthStorage,
};
use reth_ethereum::engine::local::LocalPayloadAttributesBuilder;
use reth_ethereum::node::api::PayloadAttributesBuilder;
use reth_ethereum::EthPrimitives;
use reth_ethereum_engine_primitives::{EthBuiltPayload, EthPayloadAttributes};
use std::{fmt, sync::Arc};

/// The clique node add-ons: standard eth RPC + clique engine validator +
/// noop engine API (the consensus is embedded; there is no external CL).
pub type CliqueAddOns<N> = RpcAddOns<
    N,
    EthereumEthApiBuilder,
    CliqueEngineValidatorBuilder,
    NoopEngineApiBuilder,
    BasicEngineValidatorBuilder<CliqueEngineValidatorBuilder>,
>;

/// Type configuration for a Clique `PoA` node: the regular Ethereum node with
/// the consensus component replaced by [`CliqueConsensus`].
#[derive(Debug, Default, Clone, Copy)]
pub struct CliqueNode;

impl NodeTypes for CliqueNode {
    type Primitives = EthPrimitives;
    type ChainSpec = ChainSpec;
    type Storage = EthStorage;
    type Payload = CliqueEngineTypes;
}

impl CliqueNode {
    /// Returns a [`ComponentsBuilder`] configured for a clique node — the
    /// Ethereum components with the consensus and executor swapped
    /// (no-reward execution, see [`crate::evm::CliqueEvmConfig`]).
    pub fn components<Node>() -> ComponentsBuilder<
        Node,
        EthereumPoolBuilder,
        BasicPayloadServiceBuilder<EthereumPayloadBuilder>,
        EthereumNetworkBuilder,
        CliqueExecutorBuilder,
        CliqueConsensusBuilder,
    >
    where
        Node: FullNodeTypes<
            Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>,
        >,
        <Node::Types as NodeTypes>::Payload:
            PayloadTypes<BuiltPayload = EthBuiltPayload, PayloadAttributes = EthPayloadAttributes>,
    {
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(EthereumPoolBuilder::default())
            .executor(CliqueExecutorBuilder)
            .payload(BasicPayloadServiceBuilder::default())
            .network(EthereumNetworkBuilder::default())
            .consensus(CliqueConsensusBuilder)
    }
}

impl<N> Node<N> for CliqueNode
where
    N: FullNodeTypes<Types = Self>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        BasicPayloadServiceBuilder<EthereumPayloadBuilder>,
        EthereumNetworkBuilder,
        CliqueExecutorBuilder,
        CliqueConsensusBuilder,
    >;

    type AddOns = CliqueAddOns<NodeAdapter<N>>;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components()
    }

    fn add_ons(&self) -> Self::AddOns {
        RpcAddOns::new(
            EthereumEthApiBuilder::default(),
            CliqueEngineValidatorBuilder,
            NoopEngineApiBuilder::default(),
            BasicEngineValidatorBuilder::default(),
            Default::default(),
            Identity::new(),
        )
    }
}
/// Debug-mode support (same shape as the vanilla Ethereum node): enables
/// `launch_with_debug_capabilities`, incl. the built-in
/// `--debug.rpc-consensus-ws` follower that fetches upstream blocks over RPC
/// and feeds them to the engine.
impl<N> DebugNode<N> for CliqueNode
where
    N: FullNodeTypes<Types = Self> + reth_ethereum::node::api::node::FullNodeComponents<Types = Self>,
{
    type RpcBlock = alloy_rpc_types_eth::Block;

    fn rpc_to_primitive_block(rpc_block: Self::RpcBlock) -> reth_ethereum::Block {
        rpc_block.into_consensus().convert_transactions()
    }

    fn local_payload_attributes_builder(
        chain_spec: &Self::ChainSpec,
    ) -> impl PayloadAttributesBuilder<EthPayloadAttributes> {
        LocalPayloadAttributesBuilder::new(Arc::new(chain_spec.clone()))
    }
}

/// Builds [`CliqueConsensus`] from the chain spec + the clique config
/// registered by the chain spec parser.
#[derive(Debug, Default, Clone, Copy)]
pub struct CliqueConsensusBuilder;

/// Global registry of the built consensus engine per chain id, so code after
/// launch (e.g. the binary's follow-mode wiring) can reach the exact
/// `Arc<CliqueConsensus>` the engine holds.
fn built_registry() -> &'static std::sync::Mutex<std::collections::HashMap<u64, Arc<CliqueConsensus>>>
{
    static REGISTRY: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<u64, Arc<CliqueConsensus>>>,
    > = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Returns the [`CliqueConsensus`] engine built for a chain id, if the node
/// already launched its consensus component.
pub fn built_consensus(chain_id: u64) -> Option<Arc<CliqueConsensus>> {
    built_registry().lock().unwrap().get(&chain_id).cloned()
}

/// Returns whichever consensus engine was registered first (single-chain nodes).
pub fn first_consensus() -> Option<Arc<CliqueConsensus>> {
    built_registry().lock().unwrap().values().next().cloned()
}

impl<Node> ConsensusBuilder<Node> for CliqueConsensusBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
{
    type Consensus = Arc<CliqueConsensus>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        let chain_spec = ctx.chain_spec();
        let chain_id = chain_spec.chain().id();
        let config = registered_clique_config(chain_id).ok_or_else(|| {
            eyre::eyre!(
                "no clique config registered for chain id {chain_id} — \
                 start the node with --chain <genesis.json> parsed by CliqueChainSpecParser"
            )
        })?;
        let consensus = Arc::new(CliqueConsensus::new(chain_spec, config));
        built_registry().lock().unwrap().insert(chain_id, consensus.clone());
        Ok(consensus)
    }
}

/// Adapts a reth [`HeaderProvider`] into the clique consensus's
/// [`CliqueHeaderSource`].
pub struct ProviderHeaderSource<P> {
    provider: P,
}

impl<P> fmt::Debug for ProviderHeaderSource<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderHeaderSource").finish_non_exhaustive()
    }
}

impl<P> ProviderHeaderSource<P> {
    /// Wraps the given provider as a clique header source.
    pub const fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P> clique_consensus::CliqueHeaderSource for ProviderHeaderSource<P>
where
    P: HeaderProvider<Header = Header> + Send + Sync + 'static,
{
    fn header_by_hash(&self, hash: B256) -> Option<Header> {
        self.provider.header(hash).ok().flatten()
    }

    fn header_by_number(&self, number: u64) -> Option<Header> {
        self.provider.header_by_number(number).ok().flatten()
    }
}


