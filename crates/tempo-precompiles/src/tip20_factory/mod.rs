//! [TIP-20] token factory precompile — deploys new [TIP-20] tokens at deterministic addresses.
//!
//! [TIP-20]: <https://docs.tempo.xyz/protocol/tip20>

pub mod dispatch;

pub use tempo_contracts::precompiles::{
    ITIP20Factory, TIP20FactoryError, TIP20FactoryEvent, createTokenCall, createTokenWithLogoCall,
};
use tempo_precompiles_macros::contract;

use crate::{
    PATH_USD_ADDRESS, TIP20_FACTORY_ADDRESS,
    error::{Result, TempoPrecompileError},
    tip20::{TIP20Error, TIP20Token, USD_CURRENCY},
};
use alloy::{
    primitives::{Address, B256, keccak256},
    sol_types::SolValue,
};
use tempo_primitives::TempoAddressExt;
use tracing::trace;

/// Number of reserved addresses (0 to RESERVED_SIZE-1) that cannot be deployed via factory
const RESERVED_SIZE: u64 = 1024;

/// TIP20 token address prefix (12 bytes): 0x20C000000000000000000000
const TIP20_PREFIX_BYTES: [u8; 12] = [
    0x20, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Factory contract for deploying new TIP-20 tokens at deterministic addresses.
///
/// Tokens are deployed at `TIP20_PREFIX || keccak256(sender, salt)[..8]`.
/// The first 1024 addresses are reserved for protocol-deployed tokens.
///
/// The struct fields define the on-chain storage layout; the `#[contract]` macro generates the
/// storage handlers which provide an ergonomic way to interact with the EVM state.
#[contract(addr = TIP20_FACTORY_ADDRESS)]
pub struct TIP20Factory {}

/// Computes the deterministic TIP20 address from sender and salt.
/// Returns the address and the lower bytes used for derivation.
pub(crate) fn compute_tip20_address(sender: Address, salt: B256) -> (Address, u64) {
    let hash = keccak256((sender, salt).abi_encode());

    // Take first 8 bytes of hash as lower bytes
    let mut padded = [0u8; 8];
    padded.copy_from_slice(&hash[..8]);
    let lower_bytes = u64::from_be_bytes(padded);

    // Construct the address: TIP20_PREFIX (12 bytes) || hash[..8] (8 bytes)
    let mut address_bytes = [0u8; 20];
    address_bytes[..12].copy_from_slice(&TIP20_PREFIX_BYTES);
    address_bytes[12..].copy_from_slice(&hash[..8]);

    (Address::from(address_bytes), lower_bytes)
}

// Precompile functions
impl TIP20Factory {
    /// Initializes the TIP-20 factory precompile.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Computes the deterministic address for a token given `sender` and `salt`. Reverts if the
    /// derived address falls within the reserved range (lower 8 bytes < `RESERVED_SIZE`).
    ///
    /// # Errors
    /// - `AddressReserved` — the derived address is in the reserved range
    pub fn get_token_address(&self, call: ITIP20Factory::getTokenAddressCall) -> Result<Address> {
        let (address, lower_bytes) = compute_tip20_address(call.sender, call.salt);

        // Check if address would be in reserved range
        if lower_bytes < RESERVED_SIZE {
            return Err(TempoPrecompileError::TIP20Factory(
                TIP20FactoryError::address_reserved(),
            ));
        }

        Ok(address)
    }

    /// Returns `true` if `token` has the correct TIP-20 prefix and has code deployed.
    pub fn is_tip20(&self, token: Address) -> Result<bool> {
        if !token.is_tip20() {
            return Ok(false);
        }
        // Check if the token has code deployed (non-empty code hash)
        self.storage
            .with_account_info(token, |info| Ok(!info.is_empty_code_hash()))
    }

    /// Deploys a new TIP-20 token at a deterministic address derived from `sender` and `salt`.
    ///
    /// Validates that the token does not already exist, the quote token is a deployed TIP-20 of
    /// a compatible currency, and the derived address is outside the reserved range. Initializes
    /// the token via [`TIP20Token::initialize`].
    ///
    /// # Errors
    /// - `TokenAlreadyExists` — a TIP-20 is already deployed at the derived address
    /// - `InvalidQuoteToken` — quote token is not a deployed TIP-20 or has incompatible currency
    /// - `AddressReserved` — the derived address is in the reserved range
    pub fn create_token(&mut self, sender: Address, call: createTokenCall) -> Result<Address> {
        trace!(%sender, ?call, "Create token");

        // Compute the deterministic address from sender and salt
        let (token_address, lower_bytes) = compute_tip20_address(sender, call.salt);

        if self.is_tip20(token_address)? {
            return Err(TempoPrecompileError::TIP20Factory(
                TIP20FactoryError::token_already_exists(token_address),
            ));
        }

        // Ensure that the quote token is a valid TIP20 that is currently deployed.
        if !self.is_tip20(call.quoteToken)? {
            return Err(TIP20Error::invalid_quote_token().into());
        }

        // If token is USD, its quote token must also be USD
        if call.currency == USD_CURRENCY
            && TIP20Token::from_address(call.quoteToken)?.currency()? != USD_CURRENCY
        {
            return Err(TIP20Error::invalid_quote_token().into());
        }

        // Check if address is in reserved range
        if lower_bytes < RESERVED_SIZE {
            return Err(TempoPrecompileError::TIP20Factory(
                TIP20FactoryError::address_reserved(),
            ));
        }

        TIP20Token::from_address(token_address)?.initialize(
            sender,
            &call.name,
            &call.symbol,
            &call.currency,
            call.quoteToken,
            call.admin,
        )?;

        self.emit_event(TIP20FactoryEvent::token_created(
            token_address,
            call.name,
            call.symbol,
            call.currency,
            call.quoteToken,
            call.admin,
            call.salt,
        ))?;

        Ok(token_address)
    }

    /// Creates a token and atomically sets its `logoURI` (TIP-1026).
    ///
    /// Behaves identically to [`Self::create_token`] plus, when `logoURI` is
    /// non-empty, writes the URI to the new token's storage and emits
    /// `LogoURIUpdated` from the new token's address with `updater = sender`.
    ///
    /// # Errors
    /// - All errors from [`Self::create_token`]
    /// - `LogoURITooLong` — `bytes(logoURI).length > 256`
    /// - `InvalidLogoURI` — `logoURI` is non-empty and fails validation
    pub fn create_token_with_logo(
        &mut self,
        sender: Address,
        call: createTokenWithLogoCall,
    ) -> Result<Address> {
        // Validate the logo URI up-front so a bad URI does not leave a partially-created token.
        if !call.logoURI.is_empty() {
            crate::tip20::TIP20Token::validate_logo_uri(&call.logoURI)?;
        }

        let token_address = self.create_token(
            sender,
            createTokenCall {
                name: call.name,
                symbol: call.symbol,
                currency: call.currency,
                quoteToken: call.quoteToken,
                admin: call.admin,
                salt: call.salt,
            },
        )?;

        if !call.logoURI.is_empty() {
            TIP20Token::from_address(token_address)?.write_logo_uri(sender, call.logoURI)?;
        }

        Ok(token_address)
    }

    /// Deploys a TIP-20 token at a reserved address (lower 8 bytes < `RESERVED_SIZE`). Used
    /// during genesis or hardforks to bootstrap protocol tokens like pathUSD.
    ///
    /// # Errors
    /// - `InvalidToken` — `address` does not have the TIP-20 prefix
    /// - `TokenAlreadyExists` — a TIP-20 is already deployed at `address`
    /// - `InvalidQuoteToken` — quote token is invalid, not deployed, or has incompatible
    ///   currency; pathUSD must use `Address::ZERO` as quote token
    /// - `AddressNotReserved` — the address is outside the reserved range
    pub fn create_token_reserved_address(
        &mut self,
        address: Address,
        name: &str,
        symbol: &str,
        currency: &str,
        quote_token: Address,
        admin: Address,
    ) -> Result<Address> {
        // Validate that the address has a TIP20 prefix
        if !address.is_tip20() {
            return Err(TIP20Error::invalid_token().into());
        }

        // Validate that the address is not already deployed
        if self.is_tip20(address)? {
            return Err(TempoPrecompileError::TIP20Factory(
                TIP20FactoryError::token_already_exists(address),
            ));
        }

        // quote_token must be address(0) or a valid TIP20
        if !quote_token.is_zero() {
            // pathUSD must set address(0) as the quote token
            // or the tip20 must be a valid deployed token
            if address == PATH_USD_ADDRESS || !self.is_tip20(quote_token)? {
                return Err(TIP20Error::invalid_quote_token().into());
            }
            // If token is USD, its quote token must also be USD
            if currency == USD_CURRENCY
                && TIP20Token::from_address(quote_token)?.currency()? != USD_CURRENCY
            {
                return Err(TIP20Error::invalid_quote_token().into());
            }
        }

        // Validate that the address is within the reserved range
        // Reserved addresses have their last 8 bytes represent a value < RESERVED_SIZE
        let mut padded = [0u8; 8];
        padded.copy_from_slice(&address.as_slice()[12..]);
        let lower_bytes = u64::from_be_bytes(padded);
        if lower_bytes >= RESERVED_SIZE {
            return Err(TempoPrecompileError::TIP20Factory(
                TIP20FactoryError::address_not_reserved(),
            ));
        }

        let mut token = TIP20Token::from_address(address)?;
        token.initialize(admin, name, symbol, currency, quote_token, admin)?;

        self.emit_event(TIP20FactoryEvent::token_created(
            address,
            name.into(),
            symbol.into(),
            currency.into(),
            quote_token,
            admin,
            B256::ZERO,
        ))?;

        Ok(address)
    }
}


