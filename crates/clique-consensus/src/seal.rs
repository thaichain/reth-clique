use crate::{CliqueError, EXTRA_SEAL};
use alloy_consensus::Header;
use alloy_primitives::{Address, B256, Signature};

/// Returns the hash of a header prior to it being sealed — geth's `SealHash`.
///
/// This is the keccak hash of the RLP of the header with the trailing 65-byte
/// signature stripped from extraData.
///
/// Upstream geth's `encodeSigHeader` panics when the header carries post-London
/// fields (withdrawals root, blob gas fields, parent beacon root); geth clique
/// simply never supported those forks. We define the seal hash as the RLP of
/// the full header minus the signature tail, so the rule extends naturally to
/// Shanghai/Cancun/Prague blocks. For pre-Shanghai blocks this is byte-for-byte
/// identical to geth's `SealHash`.
pub fn seal_hash(header: &Header) -> B256 {
    let mut header = header.clone();
    let extra_len = header.extra_data.len();
    // Panics like geth's CliqueRLP when extraData is too short: this avoids
    // ambiguity between "signature present" and "signature absent" forms.
    assert!(extra_len >= EXTRA_SEAL, "extraData shorter than the 65-byte seal");
    header.extra_data.truncate(extra_len - EXTRA_SEAL);
    header.hash_slow()
}

/// The RLP bytes which need to be signed for clique sealing — geth's
/// `CliqueRLP`. See [`seal_hash`] for the exact layout.
pub fn clique_rlp(header: &Header) -> alloy_primitives::Bytes {
    let mut header = header.clone();
    let extra_len = header.extra_data.len();
    assert!(extra_len >= EXTRA_SEAL, "extraData shorter than the 65-byte seal");
    header.extra_data.truncate(extra_len - EXTRA_SEAL);
    alloy_rlp::encode(&header).into()
}

/// Recovers the signer address from a signed clique header (geth's `ecrecover`).
///
/// The signature occupies the last 65 bytes of extraData with `v ∈ {0, 1}`
/// (EIP-2 normalized, *not* 27/28).
pub fn recover_signer(header: &Header) -> Result<Address, CliqueError> {
    let extra = &header.extra_data;
    if extra.len() < EXTRA_SEAL {
        return Err(CliqueError::MissingSignature);
    }
    let sig_bytes: [u8; EXTRA_SEAL] =
        extra[extra.len() - EXTRA_SEAL..].try_into().expect("65-byte slice");
    let hash = seal_hash(header);

    // `from_raw_array` normalizes v from 0/1 (or 27/28) and rejects invalid values
    let sig = Signature::from_raw_array(&sig_bytes)
        .map_err(|err| CliqueError::InvalidSignature(err.to_string()))?;
    let pubkey = sig
        .recover_from_prehash(&hash)
        .map_err(|err| CliqueError::InvalidSignature(err.to_string()))?;
    Ok(Address::from_public_key(&pubkey))
}

#[cfg(test)]
mod tests {
    use crate::EXTRA_VANITY;
    use super::*;
    use crate::test_util::{seal_sign, TEST_SIGNER_ADDR};

    #[test]
    fn seal_hash_ignores_signature_bytes() {
        let mut header = Header { number: 1, ..Default::default() };
        header.extra_data = vec![0u8; EXTRA_VANITY + EXTRA_SEAL].into();

        let unsigned_hash = seal_hash(&header);

        let mut extra = header.extra_data.to_vec();
        extra[EXTRA_VANITY..].copy_from_slice(&[0x42u8; 65]);
        let mut signed = header;
        signed.extra_data = extra.into();

        assert_eq!(unsigned_hash, seal_hash(&signed));
    }

    #[test]
    fn recover_signer_roundtrip() {
        let mut header = Header { number: 1, ..Default::default() };
        header.extra_data = vec![0u8; EXTRA_VANITY + EXTRA_SEAL].into();

        let signed = seal_sign(&header);
        assert_eq!(recover_signer(&signed).unwrap(), TEST_SIGNER_ADDR);

        // tampering with the seal must NOT recover the original signer — an
        // invalid signature may either error out or recover a different key
        let mut tampered = signed;
        let mut extra = tampered.extra_data.to_vec();
        let len = extra.len();
        extra[len - 65] ^= 0x01;
        tampered.extra_data = extra.into();
        match recover_signer(&tampered) {
            Ok(addr) => assert_ne!(addr, TEST_SIGNER_ADDR),
            Err(CliqueError::InvalidSignature(_)) => {}
            Err(err) => panic!("unexpected error: {err}"),
        }
    }

    #[test]
    fn missing_signature_is_rejected() {
        let header = Header { number: 1, extra_data: vec![0u8; 40].into(), ..Default::default() };
        assert_eq!(recover_signer(&header).unwrap_err(), CliqueError::MissingSignature);
    }

    #[test]
    fn clique_rlp_matches_seal_hash_input() {
        let mut header = Header { number: 1, ..Default::default() };
        header.extra_data = vec![0u8; EXTRA_VANITY + EXTRA_SEAL].into();
        let rlp = clique_rlp(&header);
        assert_eq!(alloy_primitives::keccak256(&rlp), seal_hash(&header));
    }
}
