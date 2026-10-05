//! Clique chain spec support — loading a geth-style clique genesis.json into
//! reth's [`ChainSpec`] plus the [`CliqueConfig`] the consensus engine needs.

use alloy_genesis::Genesis;
use clique_consensus::CliqueConfig;
use reth_chainspec::ChainSpec;
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex, OnceLock},
};

/// geth's `params.CliqueConfig` as it appears in a genesis.json `config`
/// object: `"clique": {"period": 10, "epoch": 30000}`.
#[derive(Debug, Clone, Copy, Deserialize)]
struct RawCliqueConfig {
    period: u64,
    #[serde(default)]
    epoch: u64,
}
/// A reth chain spec carrying clique consensus configuration.
#[derive(Debug, Clone)]
pub struct CliqueChainSpec {
    /// The reth chain spec (genesis header, hardforks, base fee params, ...).
    pub inner: Arc<ChainSpec>,
    /// Clique consensus configuration (period / epoch).
    pub clique: CliqueConfig,
}

impl std::ops::Deref for CliqueChainSpec {
    type Target = ChainSpec;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// An error while loading a clique chain spec.
#[derive(Debug, thiserror::Error)]
pub enum CliqueSpecError {
    /// The genesis file is not valid JSON.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// The genesis config object lacks the `clique` entry.
    #[error("genesis config is missing the \"clique\" object ({{\"period\": .., \"epoch\": ..}})")]
    MissingClique,
    /// Genesis extraData carries no signer addresses.
    #[error("can't start clique chain without signers: genesis extraData must be at least vanity(32) + signer(20) + seal(65) bytes, got {len}")]
    NoSigners {
        /// Actual extraData length in bytes.
        len: usize,
    },
    /// Genesis extraData is not vanity + N*20 bytes of signers + seal.
    #[error("clique genesis extraData must be vanity(32) + N*20 + seal(65), got {len}")]
    MalformedExtraData {
        /// Actual extraData length in bytes.
        len: usize,
    },
    /// Any other loader failure.
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Reads the `clique` object from a genesis `config` JSON object.
///
/// Note: we read it from the raw JSON rather than alloy's
/// `ChainConfig::extra_fields`, which does not reliably capture unknown
/// fields in current alloy versions.
pub fn clique_config_from_raw_config(
    config: &serde_json::Value,
) -> Result<CliqueConfig, CliqueSpecError> {
    let value = config.get("clique").ok_or(CliqueSpecError::MissingClique)?;
    let raw: RawCliqueConfig = serde_json::from_value(value.clone())?;
    // Tempo-style extension forks at the config root:
    //  - `"cliquePrecompileTime": <ts>` activates the clique extension precompile
    //  - `"t0Time": <ts>` activates the T0 precompile suite + state seeding
    //  - `"cliquePeriodChange": {"time": <ts>, "period": <seconds>}` forks the
    //    clique block period
    let precompile_time = config.get("cliquePrecompileTime").and_then(|v| v.as_u64());
    let t0_time = config.get("t0Time").and_then(|v| v.as_u64());
    let period_change = config.get("cliquePeriodChange").and_then(|v| {
        let time = v.get("time").and_then(|v| v.as_u64())?;
        let period = v.get("period").and_then(|v| v.as_u64())?;
        Some((time, period))
    });
    Ok(CliqueConfig::new(raw.period, raw.epoch)
        .with_precompile_time(precompile_time)
        .with_t0_time(t0_time)
        .with_period_change(period_change))
}

/// Validates clique-specific genesis constraints (geth `core/genesis.go`).
pub fn validate_clique_genesis(genesis: &Genesis) -> Result<(), CliqueSpecError> {
    let extra = &genesis.extra_data;
    // genesis extraData: 32B vanity + N*20B signers + 65B seal (seal is zeros
    // at genesis — unsigned)
    if extra.len() < 32 + 65 {
        return Err(CliqueSpecError::NoSigners { len: extra.len() });
    }
    let signers_bytes = extra.len() - 32 - 65;
    if !signers_bytes.is_multiple_of(20) || signers_bytes == 0 {
        return Err(CliqueSpecError::MalformedExtraData { len: extra.len() });
    }
    Ok(())
}

/// Global registry of clique configs keyed by chain id.
///
/// The chain spec parser registers the parsed config here; the node's
/// consensus builder reads it back at component-build time. This indirection
/// is needed because reth's `ChainSpec` cannot carry consensus-specific config
/// and alloy's `ChainConfig::extra_fields` does not reliably round-trip
/// unknown genesis fields.
fn registry() -> &'static StdMutex<HashMap<u64, CliqueConfig>> {
    static REGISTRY: OnceLock<StdMutex<HashMap<u64, CliqueConfig>>> = OnceLock::new();
    REGISTRY.get_or_init(|| StdMutex::new(HashMap::new()))
}

/// Registers the clique config for a chain id (called by the chain spec parser).
pub fn register_clique_config(chain_id: u64, config: CliqueConfig) {
    registry().lock().unwrap().insert(chain_id, config);
}

/// Returns the clique config registered for a chain id.
pub fn registered_clique_config(chain_id: u64) -> Option<CliqueConfig> {
    registry().lock().unwrap().get(&chain_id).copied()
}

/// Loads a clique genesis.json into a [`ChainSpec`] + [`CliqueConfig`].
///
/// Note: `terminalTotalDifficulty` must be absent (or the chain must never
/// reach it) so that Paris never activates — a clique chain is pre-merge.
pub fn load_clique_chainspec(genesis_json: &str) -> Result<CliqueChainSpec, CliqueSpecError> {
    let raw: serde_json::Value = serde_json::from_str(genesis_json)?;
    let config = raw.get("config").ok_or(CliqueSpecError::MissingClique)?;
    let clique = clique_config_from_raw_config(config)?;
    let genesis: Genesis = serde_json::from_str(genesis_json)?;
    validate_clique_genesis(&genesis)?;
    let spec = ChainSpec::from_genesis(genesis);
    Ok(CliqueChainSpec { inner: Arc::new(spec), clique })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use reth_chainspec::EthereumHardforks;

    const SIGNER: &str = "f7bd5f40687f14fa08e897a0432c29aee6813a63";

    /// Builds the genesis extraData: 32B vanity + 20B signer + 65B zero seal.
    fn extra_data_hex() -> String {
        format!("0x{}{}{}", "0".repeat(64), SIGNER, "0".repeat(130))
    }

    fn genesis_json() -> String {
        format!(
            r#"{{
                "config": {{
                    "chainId": 1707,
                    "homesteadBlock": 0, "eip150Block": 0, "eip155Block": 0, "eip158Block": 0,
                    "byzantiumBlock": 0, "constantinopleBlock": 0, "petersburgBlock": 0,
                    "istanbulBlock": 0, "muirGlacierBlock": 0, "berlinBlock": 0,
                    "londonBlock": 0, "arrowGlacierBlock": 0,
                    "clique": {{"period": 10, "epoch": 34560}}
                }},
                "difficulty": "0x1",
                "gasLimit": "0x1c9c380",
                "nonce": "0x6ab",
                "timestamp": "0x62d6b92c",
                "extraData": "{}",
                "alloc": {{}}
            }}"#,
            extra_data_hex()
        )
    }

    #[test]
    fn loads_clique_config_from_extra_fields() {
        let spec = load_clique_chainspec(&genesis_json()).unwrap();
        assert_eq!(spec.clique, CliqueConfig::new(10, 34560));
        assert_eq!(spec.chain().id(), 1707);
        // London at block 0 → genesis header carries the initial base fee,
        // exactly like geth's ToBlock (keeps the genesis hash identical).
        assert_eq!(spec.genesis_header().base_fee_per_gas, Some(1_000_000_000));
        assert!(!spec.is_paris_active_at_block(0), "clique chain must be pre-merge");
        // genesis signer list from extraData
        let signers = clique_consensus::Snapshot::signers_from_checkpoint(spec.genesis_header())
            .unwrap();
        assert_eq!(signers, vec![address!("f7bd5f40687f14fa08e897a0432c29aee6813a63")]);
    }

    #[test]
    fn rejects_genesis_without_signers() {
        let mut genesis: Genesis = serde_json::from_str(&genesis_json()).unwrap();
        genesis.extra_data = vec![0u8; 32].into();
        let json = serde_json::to_string(&genesis).unwrap();
        let err = load_clique_chainspec(&json).unwrap_err();
        assert!(err.to_string().contains("without signers"), "{err}");
    }

    #[test]
    fn rejects_genesis_without_clique_config() {
        let mut raw: serde_json::Value = serde_json::from_str(&genesis_json()).unwrap();
        raw["config"].as_object_mut().unwrap().remove("clique");
        let json = serde_json::to_string(&raw).unwrap();
        assert!(matches!(
            load_clique_chainspec(&json).unwrap_err(),
            CliqueSpecError::MissingClique
        ));
    }
}
