//! Native ZoneFactory precompile for TIP-1091.

pub mod dispatch;
pub mod portal;

use crate::{
    ZONE_FACTORY_ADDRESS,
    error::{Result, TempoPrecompileError},
    has_duplicates_metered,
    storage::{Handler, Mapping},
    tip20::TIP20Token,
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
};
use alloy::{
    primitives::{Address, B256, IntoLogData, keccak256},
    sol_types::SolValue,
};
use std::collections::{HashMap, HashSet};
use tempo_contracts::precompiles::{
    IZoneFactory, ZONE_MESSENGER_ADDRESS, ZONE_VERIFIER_ADDRESS, ZoneFactoryError,
    ZoneFactoryEvent, ZoneInfo, ZonePortalEvent, ZonePortalRole,
};
use tempo_precompiles_macros::{Storable, contract};
use tempo_primitives::TempoAddressExt;

/// Generated storage slots for ZonePortal accounts.
pub use portal::slots as zone_portal_slots;
pub use portal::{ZONE_PORTAL_PROXY_RUNTIME, ZonePortalStorage};
/// Minimum gas consumed by a successful zone creation.
pub const ZONE_CREATION_GAS: u64 = 15_000_000;

/// Maximum number of equal sequencers in a zone settlement set.
pub const MAX_SEQUENCERS: usize = 8;
/// Maximum UTF-8 byte length of enabled token metadata strings.
const MAX_TOKEN_METADATA_BYTES: usize = 31;

/// Native ZoneFactory storage.
///
/// The field order mirrors the TIP-1091 Solidity reference artifact: `nextZoneId` and `owner`
/// share slot 0, and `zones` occupies slot 1.
#[contract(addr = ZONE_FACTORY_ADDRESS)]
pub struct ZoneFactory {
    next_zone_id: u32,
    owner: Address,
    zones: Mapping<u32, ZoneInfoStorage>,
}

/// Solidity-compatible storage representation of `ZoneInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Storable)]
struct ZoneInfoStorage {
    zone_id: u32,
    portal: Address,
    access_mode: bool,
    gateway_mode: bool,
    admin: Address,
    sequencers: Vec<Address>,
    threshold: u8,
    verifier: Address,
    rpc_url: String,
}

impl From<ZoneInfoStorage> for ZoneInfo {
    fn from(value: ZoneInfoStorage) -> Self {
        Self {
            zoneId: value.zone_id,
            portal: value.portal,
            accessMode: value.access_mode,
            gatewayMode: value.gateway_mode,
            admin: value.admin,
            sequencers: value.sequencers,
            threshold: value.threshold,
            verifier: value.verifier,
            rpcUrl: value.rpc_url,
        }
    }
}

impl ZoneFactory {
    /// Returns the configured factory owner.
    pub fn owner(&self) -> Result<Address> {
        self.owner.read()
    }

    /// Atomically transfers zone-creation authority.
    pub fn transfer_ownership(
        &mut self,
        msg_sender: Address,
        call: IZoneFactory::transferOwnershipCall,
    ) -> Result<()> {
        let previous_owner = self.owner()?;
        if msg_sender != previous_owner {
            return Err(ZoneFactoryError::not_owner().into());
        }
        self.owner.write(call.newOwner)?;
        self.emit_event(ZoneFactoryEvent::ownership_transferred(
            previous_owner,
            call.newOwner,
        ))
    }

    /// Creates and initializes a deterministic ZonePortal account.
    pub fn create_zone(
        &mut self,
        msg_sender: Address,
        call: IZoneFactory::createZoneCall,
    ) -> Result<IZoneFactory::createZoneReturn> {
        self.storage.deduct_gas(ZONE_CREATION_GAS)?;

        if msg_sender != self.owner()? {
            return Err(ZoneFactoryError::not_owner().into());
        }
        if !TIP20Factory::new().is_tip20(call.params.initialToken)? {
            return Err(ZoneFactoryError::invalid_token().into());
        }
        if TIP403Registry::new()
            .registered_token_transfer_policy_id(call.params.initialToken)?
            .is_none()
        {
            return Err(ZoneFactoryError::token_transfer_policy_not_set().into());
        }
        validate_closed_loop_config(
            &mut self.storage,
            &call.params.allowedAccounts,
            &call.params.zoneGateways,
            &call.params.sequencers,
        )?;
        if call.params.admin.is_zero() {
            return Err(ZoneFactoryError::invalid_admin().into());
        }
        validate_sequencer_set(&call.params.sequencers, call.params.threshold)?;

        let zone_id = self.next_zone_id()?;
        let portal = portal_address(zone_id);

        // Read metadata before mutating factory or portal state. The TIP-20 validity check above
        // guarantees this is an initialized native token; failures remain atomic at the EVM call
        // checkpoint in production.
        let token = TIP20Token::from_address(call.params.initialToken)?;
        let token_name = token.name()?;
        let token_symbol = token.symbol()?;
        let token_currency = token.currency()?;
        validate_token_metadata(&token_name, &token_symbol, &token_currency)?;
        let token_enablement_hash = keccak256(
            (
                B256::ZERO,
                call.params.initialToken,
                token_name.clone(),
                token_symbol.clone(),
                token_currency.clone(),
            )
                .abi_encode_params(),
        );

        self.next_zone_id.write(
            zone_id
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;
        // TIP-1091 deliberately etches the canonical runtime unconditionally. The 96-bit portal
        // prefix makes pre-existing state computationally infeasible to target with CREATE2.
        ZonePortalStorage::new(portal).initialize(zone_id, &call.params, token_enablement_hash)?;

        self.zones[zone_id].write(ZoneInfoStorage {
            zone_id,
            portal,
            access_mode: call.params.accessMode,
            gateway_mode: call.params.gatewayMode,
            admin: call.params.admin,
            sequencers: call.params.sequencers.clone(),
            threshold: call.params.threshold,
            verifier: ZONE_VERIFIER_ADDRESS,
            rpc_url: call.params.rpcUrl.clone(),
        })?;

        self.storage.emit_event(
            portal,
            ZonePortalEvent::enforcement_modes_updated(
                call.params.accessMode,
                call.params.gatewayMode,
            )
            .into_log_data(),
        )?;

        self.storage.emit_event(
            portal,
            ZonePortalEvent::sequencer_set_updated(
                0,
                call.params.threshold,
                call.params.sequencers.clone(),
            )
            .into_log_data(),
        )?;

        self.storage.emit_event(
            portal,
            ZonePortalEvent::leader_updated(
                Address::ZERO,
                call.params.sequencers[0],
                1,
                self.storage.block_number(),
            )
            .into_log_data(),
        )?;

        let mut emitted_roles = HashMap::new();
        for gateway in &call.params.zoneGateways {
            let previous = emitted_roles
                .insert(*gateway, ZonePortalRole::CallbackGateway)
                .unwrap_or(ZonePortalRole::None);
            self.storage.emit_event(
                portal,
                ZonePortalEvent::role_updated(*gateway, previous, ZonePortalRole::CallbackGateway)
                    .into_log_data(),
            )?;
        }

        for account in &call.params.allowedAccounts {
            let previous = emitted_roles
                .insert(*account, ZonePortalRole::Account)
                .unwrap_or(ZonePortalRole::None);
            self.storage.emit_event(
                portal,
                ZonePortalEvent::role_updated(*account, previous, ZonePortalRole::Account)
                    .into_log_data(),
            )?;
        }

        self.storage.emit_event(
            portal,
            ZonePortalEvent::token_enabled(
                call.params.initialToken,
                token_name,
                token_symbol,
                token_currency,
            )
            .into_log_data(),
        )?;

        self.emit_event(ZoneFactoryEvent::zone_created(
            zone_id,
            portal,
            call.params.initialToken,
            call.params.accessMode,
            call.params.gatewayMode,
            call.params.admin,
            call.params.sequencers.clone(),
            call.params.threshold,
            ZONE_VERIFIER_ADDRESS,
        ))?;

        Ok(IZoneFactory::createZoneReturn {
            zoneId: zone_id,
            portal,
        })
    }

    /// Returns the next zone ID to assign.
    pub fn next_zone_id(&self) -> Result<u32> {
        self.next_zone_id.read()
    }

    /// Returns stored metadata for `zone_id`, or the zero/default record if it does not exist.
    pub fn zone(&self, zone_id: u32) -> Result<ZoneInfo> {
        Ok(self.zones[zone_id].read()?.into())
    }

    /// Returns whether `portal` is in the created ZonePortal address range.
    pub fn is_zone_portal(&self, portal: Address) -> Result<bool> {
        let Some(zone_id) = portal.zone_portal_id() else {
            return Ok(false);
        };

        Ok(zone_id < u64::from(self.next_zone_id()?))
    }
}

fn validate_token_metadata(name: &str, symbol: &str, currency: &str) -> Result<()> {
    if [name, symbol, currency]
        .into_iter()
        .any(|value| value.len() > MAX_TOKEN_METADATA_BYTES)
    {
        return Err(ZoneFactoryError::token_metadata_too_long().into());
    }
    Ok(())
}

fn validate_closed_loop_config(
    storage: &mut crate::storage::StorageCtx,
    allowed_accounts: &[Address],
    zone_gateways: &[Address],
    sequencers: &[Address],
) -> Result<()> {
    if allowed_accounts.contains(&ZONE_MESSENGER_ADDRESS) {
        return Err(ZoneFactoryError::invalid_closed_loop_config().into());
    }

    if storage.spec().is_t11() {
        if has_duplicates_metered(
            storage,
            allowed_accounts
                .iter()
                .chain(zone_gateways)
                .chain(sequencers)
                .copied(),
        )? {
            return Err(ZoneFactoryError::invalid_closed_loop_config().into());
        }
        return Ok(());
    }

    let mut seen =
        HashSet::with_capacity(allowed_accounts.len().saturating_add(zone_gateways.len()));
    seen.extend(allowed_accounts.iter().copied());
    if zone_gateways.iter().any(|gateway| seen.contains(gateway)) {
        return Err(ZoneFactoryError::invalid_closed_loop_config().into());
    }
    seen.extend(zone_gateways.iter().copied());

    if sequencers.iter().any(|sequencer| seen.contains(sequencer)) {
        return Err(ZoneFactoryError::invalid_closed_loop_config().into());
    }
    Ok(())
}

fn validate_sequencer_set(sequencers: &[Address], threshold: u8) -> Result<()> {
    if sequencers.is_empty()
        || sequencers.len() > MAX_SEQUENCERS
        || threshold == 0
        || usize::from(threshold) > sequencers.len()
    {
        return Err(ZoneFactoryError::invalid_sequencer_set().into());
    }

    for (index, sequencer) in sequencers.iter().enumerate() {
        if sequencer.is_zero() || sequencers[..index].contains(sequencer) {
            return Err(ZoneFactoryError::invalid_sequencer_set().into());
        }
    }
    Ok(())
}

/// Returns the deterministic TIP-1091 portal address for `zone_id`.
pub fn portal_address(zone_id: u32) -> Address {
    let mut bytes = [0u8; 20];
    bytes[..12].copy_from_slice(&Address::ZONE_PORTAL_PREFIX);
    bytes[12..].copy_from_slice(&u64::from(zone_id).to_be_bytes());
    Address::from(bytes)
}


