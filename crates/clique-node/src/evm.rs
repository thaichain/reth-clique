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
use alloy_rlp::Decodable as _;
use alloy_eips::{Decodable2718 as _, Encodable2718 as _};
use alloy_evm::{
    eth::{EthEvmBuilder, EthEvmContext},
    precompiles::{DynPrecompile, PrecompilesMap},
    revm::{
        context::{BlockEnv, CfgEnv, DBErrorMarker, TxEnv},
        context_interface::result::{EVMError, HaltReason},
        inspector::NoOpInspector,
        precompile::{
            PrecompileId, PrecompileOutput, PrecompileResult, PrecompileSpecId, PrecompileStatus,
            Precompiles,
        },
        primitives::hardfork::SpecId,
        Context, Inspector,
    },
    Database, EvmEnv, EvmFactory,
};
use alloy_primitives::{address, Address, B256, Bytes, U256};
use std::cell::RefCell;
use std::rc::Rc;
use tempo_precompiles::{extend_tempo_precompiles, storage::actions::StorageActions};
use tempo_precompiles::storage_credits::NonCreditableSlots;
use tempo_hardfork::TempoHardfork;
use reth_ethereum::{
    chainspec::{ChainSpec, EthChainSpec, EthereumHardfork, EthereumHardforks, ForkCondition},
    evm::{
        primitives::{
            eth::{spec::EthExecutorSpec, EthBlockExecutorFactory},
            ConfigureEvm, ConfigureEngineEvm, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor,
            NextBlockEnvAttributes,
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

/// Address of the `cliqueSealHash` precompile: `0x0000000000000000000000000000000000000c01`.
///
/// Input: the RLP encoding of a clique consensus header **including** the
/// 65-byte signature tail in `extraData` (the on-chain form). Output: the
/// 32-byte clique seal hash — feed it to the `ecrecover` precompile together
/// with `(v, r, s)` from `extraData[64..]` to recover the block's signer.
pub const CLIQUE_SEALHASH_ADDRESS: Address =
    address!("0000000000000000000000000000000000000c01");

/// Fixed gas cost of the `cliqueSealHash` precompile.
const SEALHASH_GAS: u64 = 20_000;

/// Returns a revert-style precompile output carrying `msg` as return data.
fn precompile_revert(msg: String) -> PrecompileOutput {
    PrecompileOutput {
        status: PrecompileStatus::Revert,
        gas_used: 0,
        gas_refunded: 0,
        state_gas_used: 0,
        state_gas_spilled: 0,
        reservoir: 0,
        bytes: msg.as_bytes().to_vec().into(),
    }
}

/// Computes the clique seal hash of an RLP-encoded header (see
/// [`CLIQUE_SEALHASH_ADDRESS`]).
pub fn clique_seal_hash(input: &[u8]) -> PrecompileResult {
    // NOTE: `PrecompileResult::Err` is *fatal* in revm 43 — invalid input must
    // be reported as a revert-status output instead.
    let header = match Header::decode(&mut &input[..]) {
        Ok(header) => header,
        Err(err) => return Ok(precompile_revert(format!("invalid header RLP: {err}"))),
    };
    Ok(PrecompileOutput::new(
        SEALHASH_GAS,
        clique_consensus::seal::seal_hash(&header).0.to_vec().into(),
        0,
    ))
}

/// The clique extension precompiles, paired with their addresses.
fn clique_precompiles() -> [(Address, DynPrecompile); 1] {
    [(
        CLIQUE_SEALHASH_ADDRESS,
        DynPrecompile::new(PrecompileId::Custom("cliqueSealHash".into()), |input| {
            clique_seal_hash(input.data)
        }),
    )]
}

/// EVM factory that injects extension precompiles once their fork
/// timestamps are reached (Tempo's `PrecompilesMap` pattern — no revm
/// changes required).
///
/// - `precompile_time` activates the `cliqueSealHash` precompile.
/// - `t0_time` activates the Tempo T0 core suite (stateful precompiles:
///   TIP-20 tokens + factory, TIP-403 registry, nonce manager, account
///   keychain, validator config v1/v2). Higher Tempo forks (T1+) are never
///   activated; the fee-token stack is left out for native-gas operation.
///
/// The vanilla sets are always derived from the block's `SpecId`; extension
/// precompiles are *added on top*, so activation is purely additive.
#[derive(Debug, Clone, Copy, Default)]
pub struct CliqueEvmFactory {
    /// Timestamp at which the `cliqueSealHash` precompile activates.
    precompile_time: Option<u64>,
    /// Timestamp at which the T0 precompile suite activates.
    t0_time: Option<u64>,
}

impl CliqueEvmFactory {
    /// Creates the factory with the given precompile activation timestamps.
    pub const fn new(precompile_time: Option<u64>, t0_time: Option<u64>) -> Self {
        Self { precompile_time, t0_time }
    }

    /// Builds the precompile set for a block: the vanilla set for the block's
    /// `SpecId`, extended with the extension precompiles if a fork is active.
    fn precompiles_map(&self, spec: SpecId, timestamp: U256) -> PrecompilesMap {
        let mut map =
            PrecompilesMap::from_static(Precompiles::new(PrecompileSpecId::from_spec_id(spec)));
        if self.precompile_time.is_some_and(|fork_time| timestamp >= U256::from(fork_time)) {
            map.extend_precompiles(clique_precompiles());
        }
        if self.t0_time.is_some_and(|fork_time| timestamp >= U256::from(fork_time)) {
            // Register the T0 core suite: the unconditional items in
            // `extend_tempo_precompiles` (TIP-20 + factory, TIP-403, nonce
            // manager, account keychain, validator config v1+v2). Higher
            // Tempo forks stay inactive — the spec is pinned at T0, so
            // is_t1()..is_t13() are all false. The fee-token stack
            // (TipFeeManager/StablecoinDEX) is registered by the same call
            // but is inert under native-gas fee handling.
            let mut cfg = CfgEnv::<TempoHardfork>::default();
            cfg.set_spec_and_mainnet_gas_params(TempoHardfork::T0);
            extend_tempo_precompiles(
                &mut map,
                &cfg,
                StorageActions::disabled(),
                Rc::new(RefCell::new(NonCreditableSlots::empty())),
            );
        }
        map
    }
}

impl EvmFactory for CliqueEvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>>> =
        alloy_evm::eth::EthEvm<DB, I, PrecompilesMap>;
    type Context<DB: Database> = Context<BlockEnv, TxEnv, CfgEnv<SpecId>, DB>;
    type Tx = TxEnv;
    type Error<DBError: DBErrorMarker> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(&self, db: DB, input: EvmEnv) -> Self::Evm<DB, NoOpInspector> {
        // NOTE: T0 state seeding (`crate::t0_seed`) is NOT wired here yet —
        // stateful T0 precompiles require a TempoBlockEnv-typed EVM context
        // (EvmPrecompileStorageProvider downcasts), which needs the custom
        // `CliqueEvm` wrapper (TempoEvm-style). Tracked for the T0 follow-up.
        let precompiles = self.precompiles_map(input.cfg_env.spec, input.block_env.timestamp);
        EthEvmBuilder::new(db, input).precompiles(precompiles).build()
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let precompiles = self.precompiles_map(input.cfg_env.spec, input.block_env.timestamp);
        EthEvmBuilder::new(db, input)
            .precompiles(precompiles)
            .activate_inspector(inspector)
            .build()
    }
}

/// [`ConfigureEvm`](reth_ethereum::evm::primitives::ConfigureEvm) for a clique
/// chain: vanilla Ethereum EVM with rewards disabled and clique precompiles.
#[derive(Clone)]
pub struct CliqueEvmConfig {
    /// Vanilla config used for EVM environment building (real spec), over the
    /// clique EVM factory.
    inner: EthEvmConfig<ChainSpec, CliqueEvmFactory>,
    /// Executor factory carrying the no-reward spec and the clique factory.
    executor_factory: EthBlockExecutorFactory<RethReceiptBuilder, NoRewardSpec, CliqueEvmFactory>,
    /// Vanilla block assembler (generic over the executor factory).
    assembler: EthBlockAssembler,
}

impl CliqueEvmConfig {
    /// Creates a new clique EVM config for the given chain spec.
    ///
    /// `precompile_time` activates the `cliqueSealHash` precompile and
    /// `t0_time` the T0 suite from their timestamps on; `None` disables.
    pub fn new(
        chain_spec: Arc<ChainSpec>,
        precompile_time: Option<u64>,
        t0_time: Option<u64>,
    ) -> Self {
        let evm_factory = CliqueEvmFactory::new(precompile_time, t0_time);
        let inner = EthEvmConfig::new_with_evm_factory(chain_spec.clone(), evm_factory);
        let executor_factory = EthBlockExecutorFactory::new(
            RethReceiptBuilder::default(),
            NoRewardSpec(chain_spec.clone()),
            evm_factory,
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
        EthBlockExecutorFactory<RethReceiptBuilder, NoRewardSpec, CliqueEvmFactory>;
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
        // The precompile fork time rides along in the clique config registry
        // (populated by the chain spec parser).
        let chain_id = ctx.chain_spec().chain().id();
        let clique_config = clique_chainspec::registered_clique_config(chain_id);
        let precompile_time = clique_config.as_ref().and_then(|c| c.precompile_time);
        let t0_time = clique_config.as_ref().and_then(|c| c.t0_time);
        Ok(CliqueEvmConfig::new(ctx.chain_spec(), precompile_time, t0_time))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Header, EMPTY_OMMER_ROOT_HASH};
    use alloy_evm::revm::primitives::keccak256;

    /// A signed test header whose seal hash we can verify against
    /// `clique_consensus::seal_hash`.
    fn signed_header() -> Header {
        let mut header = Header {
            parent_hash: keccak256("parent"),
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: Address::ZERO,
            state_root: keccak256("state"),
            transactions_root: keccak256("txs"),
            receipts_root: keccak256("receipts"),
            logs_bloom: Default::default(),
            difficulty: alloy_primitives::U256::from(2),
            number: 42,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 1_000,
            extra_data: {
                // vanity(32) + seal(65) with a dummy signature
                let mut extra = vec![0u8; 32];
                extra.extend_from_slice(&[0x42u8; 65]);
                extra.into()
            },
            ..Default::default()
        };
        header.mix_hash = Default::default();
        header.nonce = Default::default();
        header
    }

    #[test]
    fn seal_hash_precompile_matches_consensus() {
        let header = signed_header();
        let rlp = alloy_rlp::encode(&header);
        let out = clique_seal_hash(&rlp).unwrap();
        assert_eq!(out.status, PrecompileStatus::Success);
        assert_eq!(out.gas_used, SEALHASH_GAS);
        assert_eq!(out.bytes.as_ref(), clique_consensus::seal::seal_hash(&header).as_slice());
        // deterministic
        assert_eq!(clique_seal_hash(&rlp).unwrap().bytes, out.bytes);
    }

    #[test]
    fn seal_hash_precompile_rejects_bad_input() {
        // invalid RLP reverts (non-fatal) with the reason as return data
        let out = clique_seal_hash(&[0xde, 0xad]).unwrap();
        assert_eq!(out.status, PrecompileStatus::Revert);
        assert!(!out.bytes.is_empty());

        let empty = clique_seal_hash(&[]).unwrap();
        assert_eq!(empty.status, PrecompileStatus::Revert);
    }

    #[test]
    fn precompiles_activate_at_fork_time() {
        let factory = CliqueEvmFactory::new(Some(1_000), None);

        // before the fork: vanilla only
        let pre = factory.precompiles_map(SpecId::OSAKA, U256::from(999));
        assert!(pre.get(&CLIQUE_SEALHASH_ADDRESS).is_none());

        // at/after the fork: clique precompile present
        let post = factory.precompiles_map(SpecId::OSAKA, U256::from(1_000));
        assert!(post.get(&CLIQUE_SEALHASH_ADDRESS).is_some());
        // vanilla precompiles untouched
        assert!(post
            .get(&alloy_primitives::address!("0000000000000000000000000000000000000001"))
            .is_some());

        // fork never scheduled: never active
        let never =
            CliqueEvmFactory::new(None, None).precompiles_map(SpecId::OSAKA, U256::MAX);
        assert!(never.get(&CLIQUE_SEALHASH_ADDRESS).is_none());
    }
}
