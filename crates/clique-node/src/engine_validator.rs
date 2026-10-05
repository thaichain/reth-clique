//! Clique engine validator: accepts clique-form blocks (long extraData,
//! no withdrawals/blob fields) and delegates fork-field checks to the
//! standard engine helpers.

use crate::payload::{CliqueEngineTypes, CliqueExecutionData};
use alloy_rpc_types_engine::PayloadAttributes as EthPayloadAttributes;
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks};
use reth_engine_primitives::{EngineApiValidator, PayloadValidator};
use reth_ethereum::Block;
use reth_node_api::NodeTypes;
use reth_node_builder::{rpc::PayloadValidatorBuilder, AddOnsContext};
use reth_payload_primitives::{
    validate_version_specific_fields, EngineApiMessageVersion,
    EngineObjectValidationError, NewPayloadError, PayloadOrAttributes,
};
use reth_primitives_traits::SealedBlock;
use std::sync::Arc;

/// Tree validator for clique payloads.
///
/// `convert_payload_to_block` simply unwraps the carried sealed block — no
/// alloy payload decoding, so clique's >32-byte `extraData` passes through.
#[derive(Debug, Clone)]
pub struct CliqueEngineValidator<ChainSpec = reth_chainspec::ChainSpec> {
    chain_spec: Arc<ChainSpec>,
}

impl<ChainSpec> CliqueEngineValidator<ChainSpec> {
    /// Instantiates a new validator.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { chain_spec }
    }

    /// Returns the chain spec used by the validator.
    #[inline]
    fn chain_spec(&self) -> &ChainSpec {
        &self.chain_spec
    }
}

impl PayloadValidator<CliqueEngineTypes> for CliqueEngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
{
    type Block = Block;

    fn convert_payload_to_block(
        &self,
        payload: CliqueExecutionData,
    ) -> Result<SealedBlock<Self::Block>, NewPayloadError> {
        Ok(payload.block)
    }
}

impl EngineApiValidator<CliqueEngineTypes> for CliqueEngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, CliqueExecutionData, EthPayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        // execution requests (EIP-7685) are validated when clique chains
        // adopt Prague — the clique block format carries them in-body, so
        // there is nothing engine-API-level to check here.
        validate_version_specific_fields(self.chain_spec(), version, payload_or_attrs)
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &EthPayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(
            self.chain_spec(),
            version,
            PayloadOrAttributes::<CliqueExecutionData, EthPayloadAttributes>::PayloadAttributes(
                attributes,
            ),
        )
    }
}

/// Builds [`CliqueEngineValidator`] — the clique replacement for
/// the vanilla Ethereum engine validator builder.
#[derive(Debug, Default, Clone, Copy)]
pub struct CliqueEngineValidatorBuilder;

impl<Node, Types> PayloadValidatorBuilder<Node> for CliqueEngineValidatorBuilder
where
    Types: NodeTypes<
        ChainSpec: EthChainSpec + EthereumHardforks + Clone + 'static,
        Payload = CliqueEngineTypes,
        Primitives = reth_ethereum::EthPrimitives,
    >,
    Node: reth_ethereum::node::api::node::FullNodeComponents<Types = Types>,
    CliqueEngineValidator<Types::ChainSpec>: PayloadValidator<CliqueEngineTypes>,
{
    type Validator = CliqueEngineValidator<Types::ChainSpec>;

    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        Ok(CliqueEngineValidator::new(ctx.config.chain.clone()))
    }
}
