//! Deterministic T0 fork state seeding.
//!
//! At the first block at/after `t0Time` the T0 precompile suite needs its
//! initial state: `__initialize()` marker bytecode for each precompile
//! contract, the pathUSD protocol token (created at a reserved address with
//! the configured admin as `DEFAULT_ADMIN_ROLE` + `ISSUER_ROLE`), and the
//! ValidatorConfig owner slot.
//!
//! Like Tempo's genesis seeding (which assembles precompile state at block 0
//! via `StorageCtx::enter_evm`), we run the same precompile calls against the
//! live EVM journal. All writes are constants derived from the config, so
//! re-running them is idempotent — the state trie is unchanged after the
//! first application and every node derives the same state root.

use alloy_evm::precompiles::PrecompilesMap;
use alloy_evm::revm::context::{CfgEnv, TxEnv};
use alloy_evm::Database;
use alloy_evm::EvmInternals;
use alloy_primitives::{address, Address, U256};
use std::cell::RefCell;
use std::rc::Rc;
use tempo_contracts::precompiles::PATH_USD_ADDRESS;
use tempo_hardfork::TempoHardfork;
use tempo_primitives::TempoBlockEnv;
use tempo_precompiles::storage::evm::EvmPrecompileStorageProvider;
use tempo_precompiles::storage::{actions::StorageActions, StorageCtx};
use tempo_precompiles::storage_credits::NonCreditableSlots;
use tempo_precompiles::{
    account_keychain::AccountKeychain, nonce::NonceManager, tip20::TIP20Token,
    tip20::ISSUER_ROLE, tip20_factory::TIP20Factory, tip403_registry::TIP403Registry,
    validator_config::ValidatorConfig, validator_config_v2::ValidatorConfigV2,
};

/// The T0 administrator: owner of ValidatorConfig v1/v2 and
/// admin/issuer of the pathUSD protocol token.
pub const T0_ADMIN_ADDRESS: Address = address!("5266Dfa5ae013674f8FdC832b7c601B838D94eE6");

/// Runs the T0 seeding writes against the EVM journal.
///
/// Must only be called on blocks at/after `t0Time`; the writes are
/// idempotent constants, so calling it again is a no-op for the state trie.
pub fn seed_t0_state<J>(
    journal: &mut J,
    block_env: &TempoBlockEnv,
    cfg: &CfgEnv<TempoHardfork>,
    tx_env: &TxEnv,
    admin: Address,
) -> Result<(), String>
where
    J: alloy_evm::revm::context::JournalTr<Database: Database> + std::fmt::Debug,
{
    let internals = EvmInternals::new(journal, block_env, cfg, tx_env);
    let mut provider = EvmPrecompileStorageProvider::new(
        internals,
        u64::MAX,
        0,
        TempoHardfork::T0,
        false,
        false,
        cfg.gas_params.clone(),
    )
    .with_actions(StorageActions::disabled())
    .with_non_creditable_slots(Rc::new(RefCell::new(NonCreditableSlots::empty())));

    StorageCtx::enter(&mut provider, || -> Result<(), String> {
        TIP403Registry::new().initialize().map_err(e("TIP403Registry::initialize"))?;
        TIP20Factory::new().initialize().map_err(e("TIP20Factory::initialize"))?;

        // pathUSD at the reserved protocol address, owned/administered by the
        // T0 admin (tempo's `create_path_usd_token`, minus the genesis mints).
        TIP20Factory::new()
            .create_token_reserved_address(
                PATH_USD_ADDRESS,
                "pathUSD",
                "pathUSD",
                "USD",
                Address::ZERO,
                admin,
            )
            .map_err(e("TIP20Factory::create_token_reserved_address(pathUSD)"))?;
        let mut token = TIP20Token::from_address(PATH_USD_ADDRESS)
            .map_err(e("TIP20Token::from_address(pathUSD)"))?;
        token.grant_role_internal(admin, ISSUER_ROLE).map_err(e("pathUSD grant ISSUER_ROLE"))?;

        ValidatorConfig::new().initialize(admin).map_err(e("ValidatorConfig::initialize"))?;
        ValidatorConfigV2::new().initialize(admin).map_err(e("ValidatorConfigV2::initialize"))?;
        NonceManager::new().initialize().map_err(e("NonceManager::initialize"))?;
        AccountKeychain::new().initialize().map_err(e("AccountKeychain::initialize"))?;
        Ok(())
    })
}

/// Helper building the "seeding step X failed: {err}" message.
fn e(step: &'static str) -> impl Fn(tempo_precompiles::error::TempoPrecompileError) -> String {
    move |err| format!("T0 seeding: {step} failed: {err}")
}

/// Convenience: whether the T0 fork is active for the given block cfg/tx
/// environment (used by tests).
pub fn t0_cfg_env() -> CfgEnv<TempoHardfork> {
    let mut cfg = CfgEnv::<TempoHardfork>::default();
    cfg.set_spec_and_mainnet_gas_params(TempoHardfork::T0);
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_evm::revm::{
        context::Context, database::{CacheDB, EmptyDB}, MainContext,
    };

    /// Builds a raw journal over a TempoBlockEnv-typed context, runs seeding,
    /// and reads back the ValidatorConfig owner slot.
    fn seed_and_read_owner(timestamp: u64) -> Address {
        let mut tempo_block = TempoBlockEnv::default();
        tempo_block.inner.timestamp = U256::from(timestamp);
        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.set_spec_and_mainnet_gas_params(TempoHardfork::T0);
        let mut ctx = Context::mainnet()
            .with_block(tempo_block)
            .with_cfg(cfg)
            .with_db(CacheDB::<EmptyDB>::default());

        {
            let seed_result = seed_t0_state(
                &mut ctx.journaled_state,
                &ctx.block,
                &ctx.cfg,
                &ctx.tx,
                T0_ADMIN_ADDRESS,
            );
            assert!(seed_result.is_ok(), "seeding failed: {seed_result:?}");
        }

        let internals = EvmInternals::new(
            &mut ctx.journaled_state,
            &ctx.block,
            &ctx.cfg,
            &ctx.tx,
        );
        let mut provider = EvmPrecompileStorageProvider::new(
            internals,
            u64::MAX,
            0,
            TempoHardfork::T0,
            false,
            false,
            ctx.cfg.gas_params.clone(),
        )
        .with_actions(StorageActions::disabled());
        StorageCtx::enter(&mut provider, || ValidatorConfig::new().owner().expect("owner"))
    }

    #[test]
    fn seeding_sets_admin_as_validator_config_owner() {
        assert_eq!(seed_and_read_owner(1_000), T0_ADMIN_ADDRESS);
    }

    #[test]
    fn seeding_is_idempotent() {
        // second seeding run on the same journal keeps the same owner
        assert_eq!(seed_and_read_owner(1_000), T0_ADMIN_ADDRESS);
    }
}
