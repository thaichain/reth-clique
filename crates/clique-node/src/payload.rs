//! Clique payload types.
//!
//! [`CliqueExecutionData`] carries the full sealed block instead of an alloy
//! `ExecutionPayload`, because alloy's payload decode hard-rejects
//! `extra_data` longer than 32 bytes — clique seals are 32-byte vanity +
//! N×20-byte signers + 65-byte signature, i.e. always longer. Everything else
//! (built payload, payload attributes, engine envelopes) stays standard.

use alloy_primitives::{B256, Bytes};
use alloy_rpc_types_engine::{
    ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4,
    ExecutionPayloadEnvelopeV5, ExecutionPayloadEnvelopeV6, ExecutionPayloadV1,
};
use reth_engine_primitives::{EngineTypes, ExecutionPayload};
use reth_ethereum::Block;
use reth_payload_primitives::{BuiltPayload, PayloadTypes};
use reth_primitives_traits::{NodePrimitives, SealedBlock};
use serde::{Deserialize, Serialize};

/// Execution data for a clique chain: the sealed block itself.
///
/// Conversion from RPC/peer representations happens *outside* the engine
/// payload decoding, so clique's >32-byte `extraData` is never rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliqueExecutionData {
    /// The full sealed block (header includes the clique extraData).
    pub block: SealedBlock<Block>,
}

impl ExecutionPayload for CliqueExecutionData {
    fn parent_hash(&self) -> B256 {
        self.block.header().parent_hash
    }

    fn block_hash(&self) -> B256 {
        self.block.hash()
    }

    fn block_number(&self) -> u64 {
        self.block.header().number
    }

    fn withdrawals(&self) -> Option<&Vec<alloy_eips::eip4895::Withdrawal>> {
        self.block.body().withdrawals.as_ref().map(|w| &w.0)
    }

    fn block_access_list(&self) -> Option<&Bytes> {
        None
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.block.header().parent_beacon_block_root
    }

    fn timestamp(&self) -> u64 {
        self.block.header().timestamp
    }

    fn gas_used(&self) -> u64 {
        self.block.header().gas_used
    }

    fn gas_limit(&self) -> u64 {
        self.block.header().gas_limit
    }

    fn transaction_count(&self) -> usize {
        self.block.transaction_count()
    }

    fn slot_number(&self) -> Option<u64> {
        self.block.header().slot_number
    }
}

impl From<EthBuiltPayload> for CliqueExecutionData {
    fn from(payload: EthBuiltPayload) -> Self {
        Self { block: payload.block().clone() }
    }
}

/// Engine types for a clique chain: clique execution data, vanilla built
/// payload, vanilla payload attributes, standard engine envelopes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliqueEngineTypes;

impl PayloadTypes for CliqueEngineTypes {
    type BuiltPayload = EthBuiltPayload;
    type PayloadAttributes = EthPayloadAttributes;
    type ExecutionData = CliqueExecutionData;

    fn block_to_payload(
        block: SealedBlock<
            <<Self::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block,
        >,
        _bal: Option<Bytes>,
    ) -> Self::ExecutionData {
        Self::ExecutionData { block }
    }
}

impl EngineTypes for CliqueEngineTypes {
    type ExecutionPayloadEnvelopeV1 = ExecutionPayloadV1;
    type ExecutionPayloadEnvelopeV2 = ExecutionPayloadEnvelopeV2;
    type ExecutionPayloadEnvelopeV3 = ExecutionPayloadEnvelopeV3;
    type ExecutionPayloadEnvelopeV4 = ExecutionPayloadEnvelopeV4;
    type ExecutionPayloadEnvelopeV5 = ExecutionPayloadEnvelopeV5;
    type ExecutionPayloadEnvelopeV6 = ExecutionPayloadEnvelopeV6;
}

use reth_ethereum_engine_primitives::{EthBuiltPayload, EthPayloadAttributes};
