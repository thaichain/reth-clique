//! Clique EVM configuration.
//!
//! The one difference from a vanilla Ethereum chain: geth's clique engine
//! never pays block rewards, but reth's generic executor mints PoW-style
//! rewards (2 ETH/block post-Constantinople) whenever Paris is *inactive*.
//! A clique chain must keep Paris inactive (geth stops sealing clique blocks
//! the moment TTD is reached, and pre-merge EVM semantics — real `DIFFICULTY`
//! opcode — must be preserved), so the vanilla executor would silently mint
//! rewards into the coinbase on every block and diverge from geth.
//!
//! [`CliqueEvmConfig`] therefore splits the chain spec by consumer:
//! - **EVM env building** uses the real spec — block env, spec ids and opcode
//!   semantics stay exactly geth-clique-faithful.
//! - **The block executor** uses [`NoRewardSpec`], a wrapper that reports
//!   Paris as active so `base_block_reward` is `None`; every other fork query
//!   is delegated unchanged (Shanghai/Cancun/Prague system calls behave as
//!   scheduled).

use alloy_consensus::Header;
use alloy_eips::{Decodable2718 as _, Encodable2718 as _};
use alloy_primitives::{Address, B256, Bytes};
use reth_ethereum::{
    chainspec::{ChainSpec, EthChainSpec, EthereumHardfork, EthereumHardforks, ForkCondition},
    evm::{
        primitives::{
            eth::{spec::EthExecutorSpec, EthBlockExecutorFactory},
            ConfigureEvm, ConfigureEngineEvm, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor,
            EthEvmFactory, NextBlockEnvAttributes,
        },
        EthBlockAssembler, EthEvmConfig, RethReceiptBuilder,
    },
    node::{
        api::{node::FullNodeTypes, NodeTypes},
        builder::{components::ExecutorBuilder, BuilderContext},
    },
    primitives::{SealedHeader, SignedTransaction},
    TransactionSigned, EthPrimitives,
};
use reth_storage_errors::any::AnyError;
use std::{convert::Infallible, fmt, sync::Arc};

/// A chain spec wrapper that reports [`EthereumHardfork::Paris`] as active at
/// every block, and delegates everything else to the inner spec.
///
/// Used **only** by the block executor to suppress PoW-style block rewards.
/// See [`CliqueEvmConfig`] for the rationale.
#[derive(Debug, Clone)]
pub struct NoRewardSpec(pub Arc<ChainSpec>);

impl EthereumHardforks for NoRewardSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        self.0.ethereum_fork_activation(fork)
    }

    fn is_paris_active_at_block(&self, _block_number: u64) -> bool {
        // clique never pays block rewards; reth only skips them post-Paris
        true
    }
}

impl EthExecutorSpec for NoRewardSpec {
    fn deposit_contract_address(&self) -> Option<Address> {
        self.0.deposit_contract().map(|dc| dc.address)
    }
}

/// [`ConfigureEvm`](reth_ethereum::evm::primitives::ConfigureEvm) for a clique
/// chain: vanilla Ethereum EVM with rewards disabled.
#[derive(Clone)]
pub struct CliqueEvmConfig {
    /// Vanilla config used for EVM environment building (real spec).
    inner: EthEvmConfig,
    /// Executor factory carrying the no-reward spec.
    executor_factory: EthBlockExecutorFactory<RethReceiptBuilder, NoRewardSpec, EthEvmFactory>,
    /// Vanilla block assembler (generic over the executor factory).
    assembler: EthBlockAssembler,
}

impl CliqueEvmConfig {
    /// Creates a new clique EVM config for the given chain spec.
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        let inner = EthEvmConfig::new(chain_spec.clone());
        let executor_factory = EthBlockExecutorFactory::new(
            RethReceiptBuilder::default(),
            NoRewardSpec(chain_spec.clone()),
            EthEvmFactory::default(),
        );
        Self {
            inner,
            executor_factory,
            assembler: EthBlockAssembler::new(chain_spec),
        }
    }

    /// Returns the real chain spec used for EVM environment building.
    pub const fn chain_spec(&self) -> &Arc<ChainSpec> {
        self.inner.chain_spec()
    }
}

impl fmt::Debug for CliqueEvmConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CliqueEvmConfig").finish_non_exhaustive()
    }
}

impl reth_ethereum::evm::primitives::ConfigureEvm for CliqueEvmConfig {
    type Primitives = EthPrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory =
        EthBlockExecutorFactory<RethReceiptBuilder, NoRewardSpec, EthEvmFactory>;
    type BlockAssembler = EthBlockAssembler;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.executor_factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.assembler
    }

    fn evm_env(&self, header: &Header) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env(header)
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.next_evm_env(parent, attributes)
    }

    fn context_for_block<'a>(
        &self,
        block: &'a reth_ethereum::primitives::SealedBlock<reth_ethereum::Block>,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        let mut ctx = self.inner.context_for_block(block)?;
        self.clique_fix_beacon_root(
            &mut ctx,
            block.header().timestamp,
            block.header().parent_beacon_block_root,
        );
        Ok(ctx)
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<Header>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<ExecutionCtxFor<'_, Self>, Self::Error> {
        let ts = attributes.timestamp;
        let mut ctx = self.inner.context_for_next_block(parent, attributes)?;
        self.clique_fix_beacon_root(&mut ctx, ts, None);
        Ok(ctx)
    }
}

impl CliqueEvmConfig {
    /// Post-cancun, alloy's executor requires a parent beacon block root for
    /// the EIP-4788 syscall, but the clique header form never carries one.
    /// Supply `0x0` in the execution context (header stays clique-form) so
    /// execution proceeds identically on every clique-reth node.
    fn clique_fix_beacon_root<'a>(
        &self,
        ctx: &mut reth_ethereum::evm::primitives::eth::EthBlockExecutionCtx<'a>,
        timestamp: u64,
        header_root: Option<B256>,
    ) {
        if self.chain_spec().is_cancun_active_at_timestamp(timestamp)
            && ctx.parent_beacon_block_root.is_none()
        {
            ctx.parent_beacon_block_root = header_root.or(Some(B256::ZERO));
        }
    }
}

impl ConfigureEngineEvm<crate::payload::CliqueExecutionData> for CliqueEvmConfig {
    fn evm_env_for_payload(
        &self,
        payload: &crate::payload::CliqueExecutionData,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        // The clique execution data carries the full block: derive the env
        // from its own header (identical to the vanilla header-based path).
        self.evm_env(payload.block.header())
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a crate::payload::CliqueExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        let header = payload.block.header();
        let mut ctx = reth_ethereum::evm::primitives::eth::EthBlockExecutionCtx {
            tx_count_hint: Some(payload.block.transaction_count()),
            parent_hash: header.parent_hash,
            parent_beacon_block_root: header.parent_beacon_block_root,
            ommers: &[],
            withdrawals: None,
            extra_data: header.extra_data.clone(),
            slot_number: header.slot_number,
        };
        self.clique_fix_beacon_root(&mut ctx, header.timestamp, header.parent_beacon_block_root);
        Ok(ctx)
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &crate::payload::CliqueExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        // Same conversion shape as the vanilla config: raw 2718-encoded txs
        // plus a decode+recover closure.
        let txs: Vec<Bytes> = payload
            .block
            .body()
            .transactions()
            .map(|tx| alloy_primitives::Bytes::from(tx.encoded_2718()))
            .collect();
        let convert = move |tx: Bytes| {
            let tx = TransactionSigned::decode_2718_exact(tx.as_ref()).map_err(AnyError::new)?;
            let signer = tx.try_recover().map_err(AnyError::new)?;
            Ok::<_, AnyError>(tx.with_signer(signer))
        };
        Ok((txs, convert))
    }
}

/// Builds [`CliqueEvmConfig`] — the clique replacement for the vanilla
/// Ethereum executor builder.
#[derive(Debug, Default, Clone, Copy)]
pub struct CliqueExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for CliqueExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
{
    type EVM = CliqueEvmConfig;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        Ok(CliqueEvmConfig::new(ctx.chain_spec()))
    }
}
