//! Tempo precompile implementations.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
pub use error::{EncodePrecompileResult, IntoPrecompileResult, Result};

pub mod storage;

pub mod dispatch;
pub use dispatch::*;

pub(crate) mod ip_validation;

pub mod account_keychain;
pub mod address_registry;
pub mod current_committee;
pub mod nonce;
pub mod receive_policy_guard;
pub mod signature_verifier;
pub mod stablecoin_dex;
pub mod storage_credits;
pub mod tip20;
pub mod tip20_channel_reserve;
pub mod tip20_factory;
pub mod tip403_registry;
pub mod tip_fee_manager;
pub mod validator_config;
pub mod validator_config_v2;
pub mod zone_factory;

// NOTE(vendored): `test_util` and `tests/storage_tests` (Solidity conformance
// harness) trimmed from this vendored copy.

use crate::{
    account_keychain::AccountKeychain,
    address_registry::AddressRegistry,
    current_committee::CurrentCommittee,
    nonce::NonceManager,
    receive_policy_guard::ReceivePolicyGuard,
    signature_verifier::SignatureVerifier,
    stablecoin_dex::StablecoinDEX,
    storage::{StorageCtx, actions::StorageActions},
    storage_credits::{NonCreditableSlots, StorageCredits},
    tip_fee_manager::TipFeeManager,
    tip20::TIP20Token,
    tip20_channel_reserve::TIP20ChannelReserve,
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
    validator_config::ValidatorConfig,
    validator_config_v2::ValidatorConfigV2,
    zone_factory::ZoneFactory,
};
use std::{cell::RefCell, rc::Rc};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::TempoAddressExt;

#[cfg(test)]
use alloy::sol_types::SolInterface;
use alloy::{primitives::Address, sol, sol_types::SolError};
use alloy_evm::precompiles::{DynPrecompile, PrecompilesMap};
use revm::{
    context::CfgEnv,
    handler::EthPrecompiles,
    precompile::{PrecompileId, PrecompileOutput, PrecompileResult},
    primitives::hardfork::SpecId,
};

pub use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, ADDRESS_REGISTRY_ADDRESS, CURRENT_COMMITTEE_ADDRESS,
    DEFAULT_FEE_TOKEN, NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS, RECEIVE_POLICY_GUARD_ADDRESS,
    SIGNATURE_VERIFIER_ADDRESS, STABLECOIN_DEX_ADDRESS, STORAGE_CREDITS_ADDRESS,
    SYSTEM_PRECOMPILES, TIP_FEE_MANAGER_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS,
    TIP20_FACTORY_ADDRESS, TIP403_REGISTRY_ADDRESS, VALIDATOR_CONFIG_ADDRESS,
    VALIDATOR_CONFIG_V2_ADDRESS, ZONE_FACTORY_ADDRESS, ZONE_MESSENGER_ADDRESS,
    ZONE_PORTAL_IMPL_ADDRESS, ZONE_VERIFIER_ADDRESS,
};

// Re-export storage layout helpers for read-only contexts (e.g., pool validation)
pub use account_keychain::AuthorizedKey;

/// Pre-T11 input per word cost. It covers ABI decoding and cloning of input into calldata.
///
/// This is priced at twice `COPY_COST` to mitigate different ABI decodings.
const PRE_T11_INPUT_PER_WORD_COST: u64 = 6;

/// Input per word cost starting at T11.
const POST_T11_INPUT_PER_WORD_COST: u64 = 30;

/// Additional T11 cost per value processed by duplicate validation.
const T11_DEDUP_PER_ITEM_COST: u64 = 20;

/// Gas cost for `ecrecover` signature verification (used by KeyAuthorization and Permit).
pub const ECRECOVER_GAS: u64 = 3_000;

/// Returns the gas cost for decoding calldata of the given length at `spec`, rounded up to word
/// boundaries, or out-of-gas if the cost cannot be represented as a `u64`.
#[inline]
pub fn input_cost(spec: TempoHardfork, calldata_len: usize) -> Result<u64> {
    let per_word_cost = if spec.is_t11() {
        POST_T11_INPUT_PER_WORD_COST
    } else {
        PRE_T11_INPUT_PER_WORD_COST
    };

    let calldata_len =
        u64::try_from(calldata_len).map_err(|_| error::TempoPrecompileError::OutOfGas)?;

    calldata_len
        .div_ceil(32)
        .checked_mul(per_word_cost)
        .ok_or(error::TempoPrecompileError::OutOfGas)
}

/// Returns the additional gas cost for duplicate validation at `spec`.
#[inline]
pub fn dedup_cost(spec: TempoHardfork, item_count: usize) -> Result<u64> {
    if !spec.is_t11() {
        return Ok(0);
    }

    u64::try_from(item_count)
        .map_err(|_| error::TempoPrecompileError::OutOfGas)?
        .checked_mul(T11_DEDUP_PER_ITEM_COST)
        .ok_or(error::TempoPrecompileError::OutOfGas)
}

/// Charges for duplicate validation, then returns whether `values` contains duplicates.
#[inline]
pub fn has_duplicates_metered<T: Ord>(
    storage: &mut StorageCtx,
    values: impl IntoIterator<Item = T>,
) -> Result<bool> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    storage.deduct_gas(dedup_cost(storage.spec(), values.len())?)?;
    values.sort_unstable();
    Ok(values.windows(2).any(|pair| pair[0] == pair[1]))
}

/// Trait implemented by all Tempo precompile contract types.
///
/// Precompiles must provide a dispatcher that decodes the 4-byte function selector from calldata,
/// ABI-decodes the arguments, and routes to the corresponding method.
pub trait Precompile {
    /// Dispatches an EVM call to this precompile.
    ///
    /// Implementations should deduct calldata gas upfront via [`input_cost`], then decode the
    /// 4-byte function selector from `calldata` and route to the matching method using
    /// `dispatch_call` combined with the `view` or `mutate` helpers.
    ///
    /// Business-logic errors are returned as reverted [`PrecompileOutput`]s with ABI-encoded
    /// error data, while fatal failures (e.g. out-of-gas) are returned as
    /// [`PrecompileError`](revm::precompile::PrecompileError).
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult;
}

/// Shared execution environment captured by Tempo precompile wrappers.
#[derive(Clone)]
pub struct PrecompileEnv {
    cfg: CfgEnv<TempoHardfork>,
    actions: StorageActions,
    non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
}

impl PrecompileEnv {
    pub fn new(
        cfg: &CfgEnv<TempoHardfork>,
        actions: StorageActions,
        non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    ) -> Self {
        Self {
            cfg: cfg.clone(),
            actions,
            non_creditable_slots,
        }
    }
}

/// Returns the full Tempo precompile set for the given EVM config.
///
/// Pre-T1C hardforks use Prague built-in precompiles; T1C+ uses Osaka built-ins. Tempo-specific
/// precompiles are then registered via [`extend_tempo_precompiles`].
///
/// [`StorageActions`] records logical precompile storage operations (`SLOAD`, `SSTORE`, `SINC`,
/// `SDEC`, and domain-specific actions such as `FeeAmmSwap`) for node/validator/builder
/// integrations that use the trace for performance; tooling can pass [`StorageActions::disabled`].
///
/// [`NonCreditableSlots`] identifies transaction-local protocol slots whose clears must not mint
/// TIP-1060 storage credits: the fee payer's fee-token balance and, when applicable, the keychain
/// fee key's spending limit. They are part of credit/gas accounting, so gas estimation should pass
/// values derived from the real transaction context rather than mocks.
pub fn tempo_precompiles(
    cfg: &CfgEnv<TempoHardfork>,
    actions: StorageActions,
    non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
) -> PrecompilesMap {
    let spec = if cfg.spec.is_t1c() {
        cfg.spec.into()
    } else {
        SpecId::PRAGUE
    };
    let mut precompiles = PrecompilesMap::from_static(EthPrecompiles::new(spec).precompiles);
    extend_tempo_precompiles(&mut precompiles, cfg, actions, non_creditable_slots);
    precompiles
}

/// Registers Tempo-specific precompiles into an existing [`PrecompilesMap`] by installing a
/// lookup function that matches addresses to their precompile: TIP-20 tokens (by prefix),
/// TIP20Factory, TIP403Registry, TipFeeManager, StablecoinDEX, NonceManager, ValidatorConfig,
/// AccountKeychain, ValidatorConfigV2, and CurrentCommittee. Each precompile is wrapped via the
/// `tempo_precompile!` macro which enforces direct-call-only (no delegatecall) and sets up the
/// storage context.
///
/// `actions` and `non_creditable_slots` are shared across all wrappers; see [`tempo_precompiles`].
pub fn extend_tempo_precompiles(
    precompiles: &mut PrecompilesMap,
    cfg: &CfgEnv<TempoHardfork>,
    actions: StorageActions,
    non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
) {
    let env = PrecompileEnv::new(cfg, actions, non_creditable_slots);

    precompiles.set_precompile_lookup(move |address: &Address| {
        if address.is_tip20() {
            Some(TIP20Token::create_precompile(*address, &env))
        } else if *address == TIP20_FACTORY_ADDRESS {
            Some(TIP20Factory::create_precompile(&env))
        } else if *address == TIP20_CHANNEL_RESERVE_ADDRESS && env.cfg.spec.is_t5() {
            Some(TIP20ChannelReserve::create_precompile(&env))
        } else if *address == ADDRESS_REGISTRY_ADDRESS && env.cfg.spec.is_t3() {
            Some(AddressRegistry::create_precompile(&env))
        } else if *address == TIP403_REGISTRY_ADDRESS {
            Some(TIP403Registry::create_precompile(&env))
        } else if *address == TIP_FEE_MANAGER_ADDRESS {
            Some(TipFeeManager::create_precompile(&env))
        } else if *address == STABLECOIN_DEX_ADDRESS {
            Some(StablecoinDEX::create_precompile(&env))
        } else if *address == NONCE_PRECOMPILE_ADDRESS {
            Some(NonceManager::create_precompile(&env))
        } else if *address == VALIDATOR_CONFIG_ADDRESS {
            Some(ValidatorConfig::create_precompile(&env))
        } else if *address == ACCOUNT_KEYCHAIN_ADDRESS {
            Some(AccountKeychain::create_precompile(&env))
        } else if *address == VALIDATOR_CONFIG_V2_ADDRESS {
            Some(ValidatorConfigV2::create_precompile(&env))
        } else if *address == SIGNATURE_VERIFIER_ADDRESS && env.cfg.spec.is_t3() {
            Some(SignatureVerifier::create_precompile(&env))
        } else if *address == RECEIVE_POLICY_GUARD_ADDRESS && env.cfg.spec.is_t6() {
            Some(ReceivePolicyGuard::create_precompile(&env))
        } else if *address == STORAGE_CREDITS_ADDRESS && env.cfg.spec.is_t7() {
            Some(StorageCredits::create_precompile(&env))
        } else if *address == CURRENT_COMMITTEE_ADDRESS && env.cfg.spec.is_t8() {
            Some(CurrentCommittee::create_precompile(&env))
        } else if *address == ZONE_FACTORY_ADDRESS && env.cfg.spec.is_t10() {
            Some(ZoneFactory::create_precompile(&env))
        } else {
            None
        }
    });
}

sol! {
    error DelegateCallNotAllowed();
}

macro_rules! tempo_precompile {
    ($id:expr, $cfg:expr, |$input:ident| $impl:expr) => {{
        #[cfg(not(test))]
        compile_error!("tempo_precompile! without actions is only available in tests");
        #[cfg(test)]
        let env = PrecompileEnv::new(
            $cfg,
            StorageActions::disabled(),
            Rc::new(RefCell::new(NonCreditableSlots::empty())),
        );
        tempo_precompile!($id, env: &env, |$input| $impl)
    }};
    ($id:expr, env: $env:expr, |$input:ident| $impl:expr) => {{
        let env: &PrecompileEnv = $env;
        let spec = env.cfg.spec;
        let amsterdam_eip8037_enabled = env.cfg.enable_amsterdam_eip8037;
        let gas_params = env.cfg.gas_params.clone();
        let actions = env.actions.clone();
        let non_creditable_slots = env.non_creditable_slots.clone();
        DynPrecompile::new_stateful(PrecompileId::Custom($id.into()), move |$input| {
            if !$input.is_direct_call() {
                return Ok(PrecompileOutput::revert(
                    0,
                    DelegateCallNotAllowed {}.abi_encode().into(),
                    $input.reservoir,
                ));
            }
            let mut storage = crate::storage::evm::EvmPrecompileStorageProvider::new(
                $input.internals,
                $input.gas,
                $input.reservoir,
                spec,
                amsterdam_eip8037_enabled,
                $input.is_static,
                gas_params.clone(),
            )
            .with_actions(actions.clone())
            .with_non_creditable_slots(non_creditable_slots.clone());
            crate::storage::StorageCtx::enter(&mut storage, || {
                $impl.call($input.data, $input.caller)
            })
        })
    }};
}

impl TipFeeManager {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("TipFeeManager", env: env, |input| { Self::new() })
    }
}

impl AddressRegistry {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("AddressRegistry", env: env, |input| { Self::new() })
    }
}

impl TIP403Registry {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("TIP403Registry", env: env, |input| { Self::new() })
    }
}

impl TIP20Factory {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("TIP20Factory", env: env, |input| { Self::new() })
    }
}

impl TIP20Token {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(address: Address, env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("TIP20Token", env: env, |input| {
            Self::from_address(address).expect("TIP20 prefix already verified")
        })
    }
}

impl ZoneFactory {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("ZoneFactory", env: env, |input| { Self::new() })
    }
}

impl StablecoinDEX {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("StablecoinDEX", env: env, |input| { Self::new() })
    }
}

impl NonceManager {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("NonceManager", env: env, |input| { Self::new() })
    }
}

impl AccountKeychain {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("AccountKeychain", env: env, |input| { Self::new() })
    }
}

impl ValidatorConfig {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("ValidatorConfig", env: env, |input| { Self::new() })
    }
}

impl ValidatorConfigV2 {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("ValidatorConfigV2", env: env, |input| { Self::new() })
    }
}

impl CurrentCommittee {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("CurrentCommittee", env: env, |input| { Self::new() })
    }
}

impl SignatureVerifier {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("SignatureVerifier", env: env, |input| { Self::new() })
    }
}

impl TIP20ChannelReserve {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("TIP20ChannelReserve", env: env, |input| { Self::new() })
    }
}

impl ReceivePolicyGuard {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("ReceivePolicyGuard", env: env, |input| { Self::new() })
    }
}

impl StorageCredits {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("StorageCredits", env: env, |input| { Self::new() })
    }
}

/// Asserts that `result` is a reverted output whose bytes decode to `expected_error`.
#[cfg(test)]
pub fn expect_precompile_revert<E>(result: &PrecompileResult, expected_error: E)
where
    E: SolInterface + PartialEq + std::fmt::Debug,
{
    match result {
        Ok(result) => {
            assert!(result.is_revert());
            let decoded = E::abi_decode(&result.bytes).unwrap();
            assert_eq!(decoded, expected_error);
        }
        Err(other) => {
            panic!("expected reverted output, got: {other:?}");
        }
    }
}


