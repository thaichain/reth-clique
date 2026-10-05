//! Clique vote snapshot — a port of geth v1.13.15 `consensus/clique/snapshot.go`.

use crate::{error::CliqueError, seal::recover_signer, CliqueConfig, EXTRA_VANITY};
use alloy_consensus::{BlockHeader, Header};
use alloy_primitives::{Address, B256};
use reth_primitives_traits::SealedHeader;
use std::collections::{BTreeSet, HashMap};

/// A single vote that an authorized signer made to modify the list of authorizations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vote {
    /// Authorized signer that cast this vote.
    pub signer: Address,
    /// Block number the vote was cast in (expires old votes).
    pub block: u64,
    /// Account being voted on to change its authorization.
    pub address: Address,
    /// Whether to authorize or deauthorize the voted account.
    pub authorize: bool,
}

/// A simple vote tally to keep the current score of votes. Votes that go
/// against the proposal aren't counted since it's equivalent to not voting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tally {
    /// Whether the vote is about authorizing or kicking someone.
    pub authorize: bool,
    /// Number of votes until now wanting to pass the proposal.
    pub votes: usize,
}

/// The state of the authorization voting at a given point in time.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Clique chain configuration.
    pub config: CliqueConfig,
    /// Block number where the snapshot was created.
    pub number: u64,
    /// Block hash where the snapshot was created.
    pub hash: B256,
    /// Set of authorized signers at this moment.
    pub signers: BTreeSet<Address>,
    /// Set of recent signers for spam protection: `block number -> signer`.
    pub recents: HashMap<u64, Address>,
    /// List of votes cast in chronological order.
    pub votes: Vec<Vote>,
    /// Current vote tally to avoid recalculating.
    pub tally: HashMap<Address, Tally>,
}

impl Snapshot {
    /// Creates a new snapshot with the specified startup parameters. The set of
    /// recent signers is left empty, so this is only valid for the genesis block
    /// and trusted epoch checkpoints (mirrors geth `newSnapshot`).
    pub fn new(config: CliqueConfig, number: u64, hash: B256, signers: impl IntoIterator<Item = Address>) -> Self {
        Self {
            config,
            number,
            hash,
            signers: signers.into_iter().collect(),
            recents: HashMap::new(),
            votes: Vec::new(),
            tally: HashMap::new(),
        }
    }

    /// Extracts the initial signer list from a genesis / checkpoint header's
    /// extraData (the bytes between the vanity and the seal).
    pub fn signers_from_checkpoint(header: &Header) -> Result<Vec<Address>, CliqueError> {
        let extra = &header.extra_data;
        if extra.len() < EXTRA_VANITY + crate::EXTRA_SEAL {
            return Err(CliqueError::MissingSignature);
        }
        let signers_bytes = &extra[EXTRA_VANITY..extra.len() - crate::EXTRA_SEAL];
        if !signers_bytes.len().is_multiple_of(crate::ADDR_LENGTH) {
            return Err(CliqueError::InvalidCheckpointSigners);
        }
        Ok(signers_bytes
            .chunks_exact(crate::ADDR_LENGTH)
            .map(Address::from_slice)
            .collect())
    }

    /// Returns the list of authorized signers in ascending order.
    pub fn signers_sorted(&self) -> Vec<Address> {
        self.signers.iter().copied().collect()
    }

    /// Returns whether the given signer is in-turn at the given block height.
    pub fn inturn(&self, number: u64, signer: Address) -> bool {
        let signers = self.signers_sorted();
        let len = signers.len() as u64;
        if len == 0 {
            return false;
        }
        let offset = signers.iter().position(|s| *s == signer).unwrap_or(len as usize) as u64;
        number % len == offset
    }

    /// Returns whether it makes sense to cast the specified vote in the given
    /// snapshot context (e.g. don't try to add an already authorized signer).
    pub fn valid_vote(&self, address: Address, authorize: bool) -> bool {
        let is_signer = self.signers.contains(&address);
        (is_signer && !authorize) || (!is_signer && authorize)
    }

    /// Adds a new vote into the tally, returning `false` if the vote is meaningless.
    fn cast(&mut self, address: Address, authorize: bool) -> bool {
        if !self.valid_vote(address, authorize) {
            return false;
        }
        self.tally
            .entry(address)
            .and_modify(|t| t.votes += 1)
            .or_insert(Tally { authorize, votes: 1 });
        true
    }

    /// Removes a previously cast vote from the tally, returning `false` if
    /// there is no matching tally.
    fn uncast(&mut self, address: Address, authorize: bool) -> bool {
        match self.tally.get_mut(&address) {
            Some(tally) if tally.authorize == authorize => {
                if tally.votes > 1 {
                    tally.votes -= 1;
                } else {
                    self.tally.remove(&address);
                }
                true
            }
            _ => false,
        }
    }

    /// Creates a new authorization snapshot by applying the given headers to
    /// this one (geth `Snapshot.apply`).
    ///
    /// `recover` resolves the signer of a header; pass [`crate::seal::recover_signer`].
    /// Headers must be in ascending order and contiguous.
    pub fn apply(
        &self,
        headers: &[SealedHeader],
        recover: impl Fn(&Header) -> Result<Address, CliqueError>,
    ) -> Result<Self, CliqueError> {
        // Sanity check that the headers can be applied
        for pair in headers.windows(2) {
            if pair[1].number() != pair[0].number() + 1 {
                return Err(CliqueError::InvalidVotingChain);
            }
        }
        if headers[0].number() != self.number + 1 {
            return Err(CliqueError::InvalidVotingChain);
        }

        let mut snap = self.clone();

        for header in headers {
            let number = header.number();

            // Remove any votes on checkpoint blocks
            if number % snap.config.epoch == 0 {
                snap.votes.clear();
                snap.tally.clear();
            }

            // Delete the oldest signer from the recent list to allow it signing again
            let limit = snap.signers.len() as u64 / 2 + 1;
            if number >= limit {
                snap.recents.remove(&(number - limit));
            }

            // Resolve the authorization key and check against signers
            let signer = recover(header.header())?;
            if !snap.signers.contains(&signer) {
                return Err(CliqueError::UnauthorizedSigner);
            }
            if snap.recents.values().any(|recent| *recent == signer) {
                return Err(CliqueError::RecentlySigned);
            }
            snap.recents.insert(number, signer);

            // Header authorized, discard any previous votes from the signer
            let coinbase = header.beneficiary();
            if let Some(idx) =
                snap.votes.iter().position(|vote| vote.signer == signer && vote.address == coinbase)
            {
                let vote = snap.votes.remove(idx);
                snap.uncast(vote.address, vote.authorize);
            }

            // Tally up the new vote from the header's coinbase/nonce
            let authorize = match header.nonce() {
                Some(n) if n == crate::NONCE_AUTH_VOTE => true,
                Some(n) if n == crate::NONCE_DROP_VOTE => false,
                // a header without a nonce field is treated as a drop vote
                None => false,
                Some(_) => return Err(CliqueError::InvalidVote),
            };
            if snap.cast(coinbase, authorize) {
                snap.votes.push(Vote { signer, block: number, address: coinbase, authorize });
            }

            // If the vote passed, update the list of signers
            let passed = snap.tally.get(&coinbase).is_some_and(|t| t.votes > snap.signers.len() / 2);
            if passed {
                let tally = snap.tally[&coinbase];
                if tally.authorize {
                    snap.signers.insert(coinbase);
                } else {
                    snap.signers.remove(&coinbase);

                    // Signer list shrunk, delete any leftover recent caches
                    let limit = snap.signers.len() as u64 / 2 + 1;
                    if number >= limit {
                        snap.recents.remove(&(number - limit));
                    }
                    // Discard any previous votes the deauthorized signer cast
                    let mut i = 0;
                    while i < snap.votes.len() {
                        if snap.votes[i].signer == coinbase {
                            let vote = snap.votes.remove(i);
                            snap.uncast(vote.address, vote.authorize);
                        } else {
                            i += 1;
                        }
                    }
                }
                // Discard any previous votes around the just changed account
                snap.votes.retain(|vote| vote.address != coinbase);
                snap.tally.remove(&coinbase);
            }
        }

        snap.number += headers.len() as u64;
        snap.hash = headers[headers.len() - 1].hash();
        Ok(snap)
    }

    /// Verifies that the header's seal is valid for this snapshot: authorized
    /// signer, not within the recent-signer protection window, and difficulty
    /// matching the turn (geth `verifySeal`). Uses real secp256k1 recovery.
    pub fn verify_seal(&self, header: &Header, number: u64) -> Result<Address, CliqueError> {
        self.verify_seal_with(header, number, recover_signer)
    }

    /// Verifies the sealer's authority WITHOUT clique difficulty/turn
    /// semantics — used for post-merge "tempo form" blocks where the seal in
    /// extraData is purely an authority proof.
    pub fn verify_authorization(
        &self,
        header: &Header,
        number: u64,
        recover: impl Fn(&Header) -> Result<Address, CliqueError>,
    ) -> Result<Address, CliqueError> {
        if number == 0 {
            return Err(CliqueError::UnknownBlock);
        }
        let signer = recover(header)?;
        if !self.signers.contains(&signer) {
            return Err(CliqueError::UnauthorizedSigner);
        }
        let limit = self.signers.len() as u64 / 2 + 1;
        if number >= limit {
            for (seen, recent) in &self.recents {
                if *recent == signer && *seen > number - limit {
                    return Err(CliqueError::RecentlySigned);
                }
            }
        }
        Ok(signer)
    }

    /// [`Self::verify_seal`] with an injectable signer-recovery function.
    pub fn verify_seal_with(
        &self,
        header: &Header,
        number: u64,
        recover: impl Fn(&Header) -> Result<Address, CliqueError>,
    ) -> Result<Address, CliqueError> {
        if number == 0 {
            return Err(CliqueError::UnknownBlock);
        }
        let signer = recover(header)?;
        if !self.signers.contains(&signer) {
            return Err(CliqueError::UnauthorizedSigner);
        }
        // Signer is among recents: only fail if the current block doesn't shift it out
        let limit = self.signers.len() as u64 / 2 + 1;
        if number >= limit {
            for (seen, recent) in &self.recents {
                if *recent == signer && *seen > number - limit {
                    return Err(CliqueError::RecentlySigned);
                }
            }
        }
        // Ensure the difficulty corresponds to the turn-ness of the signer
        let expected = if self.inturn(number, signer) { crate::DIFF_INTURN } else { crate::DIFF_NOTURN };
        if header.difficulty() != expected {
            return Err(CliqueError::WrongDifficulty);
        }
        Ok(signer)
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::*;
    use super::*;
    

    #[test]
    fn inturn_matches_signer_index() {
        let snap = snapshot_with_signers(&[addr_a(), addr_b(), addr_c()]);
        // sorted ascending: [a, b, c]
        assert_eq!(snap.signers_sorted(), vec![addr_a(), addr_b(), addr_c()]);
        assert!(snap.inturn(0, addr_a()));
        assert!(snap.inturn(1, addr_b()));
        assert!(snap.inturn(2, addr_c()));
        assert!(snap.inturn(3, addr_a()));
        assert!(!snap.inturn(3, addr_b()));
    }

    #[test]
    fn vote_passes_at_strict_majority() {
        let snap = snapshot_with_signers(&[addr_a(), addr_b(), addr_c()]);
        // 3 signers: majority needs > 1.5, i.e. 2 votes
        let headers = vec![
            sealed_vote(1, addr_a(), addr_d(), true),
            sealed_vote(2, addr_b(), addr_d(), true),
        ];
        let next = snap.apply(&headers, recover_ok).unwrap();
        assert!(next.signers.contains(&addr_d()));
        // votes/tally around the changed account are discarded
        assert!(next.votes.is_empty());
        assert!(next.tally.is_empty());
    }

    #[test]
    fn vote_fails_without_majority() {
        let snap = snapshot_with_signers(&[addr_a(), addr_b(), addr_c()]);
        let headers = vec![sealed_vote(1, addr_a(), addr_d(), true)];
        let next = snap.apply(&headers, recover_ok).unwrap();
        assert!(!next.signers.contains(&addr_d()));
        assert_eq!(next.tally[&addr_d()].votes, 1);
    }

    #[test]
    fn votes_are_per_target() {
        let snap = snapshot_with_signers(&[addr_a(), addr_b(), addr_c()]);
        // a votes auth d at block 1; blocks 2-3 by other signers; a is freed
        // from recents at block 3 (limit=2, block 3 removes recents[1]) and
        // votes auth e at block 4 — geth keeps one vote PER TARGET, so both
        // the vote for d and the vote for e stay pending.
        let headers = vec![
            sealed_vote(1, addr_a(), addr_d(), true),
            sealed_vote(2, addr_b(), Address::ZERO, false),
            sealed_vote(3, addr_c(), Address::ZERO, false),
            sealed_vote(4, addr_a(), addr_e(), true),
        ];
        let next = snap.apply(&headers, recover_ok).unwrap();
        assert_eq!(next.tally[&addr_d()].votes, 1);
        assert_eq!(next.tally[&addr_e()].votes, 1);
        assert_eq!(next.votes.len(), 2);
        // re-voting for the SAME target replaces the previous vote (not a
        // second tally entry)
        let h5 = sealed_vote(5, addr_b(), Address::ZERO, false);
        let next = next.apply(&[h5], recover_ok).unwrap();
        let h6 = sealed_vote(6, addr_a(), addr_d(), true);
        let next = next.apply(&[h6], recover_ok).unwrap();
        assert_eq!(next.tally[&addr_d()].votes, 1);
        assert_eq!(next.votes.iter().filter(|v| v.address == addr_d()).count(), 1);
    }

    #[test]
    fn invalid_votes_are_ignored() {
        let snap = snapshot_with_signers(&[addr_a(), addr_b(), addr_c()]);
        // authorizing an existing signer / dropping a non-signer are no-ops
        let headers = vec![
            sealed_vote(1, addr_a(), addr_b(), true),   // b is already a signer
            sealed_vote(2, addr_b(), addr_d(), false),  // d is not a signer
        ];
        let next = snap.apply(&headers, recover_ok).unwrap();
        assert!(next.tally.is_empty());
        assert!(next.votes.is_empty());
    }

    #[test]
    fn checkpoint_clears_votes() {
        let config = CliqueConfig::new(10, 2); // tiny epoch: block 2 is a checkpoint
        let snap = Snapshot::new(config, 0, B256::ZERO, [addr_a(), addr_b(), addr_c()]);
        let headers = vec![sealed_vote(1, addr_a(), addr_d(), true), sealed_checkpoint(2)];
        let next = snap.apply(&headers, recover_ok).unwrap();
        assert!(next.tally.is_empty(), "votes must be wiped on epoch boundary");
        // checkpoint extraData carries the signer list
        let header = headers[1].header();
        let signers = Snapshot::signers_from_checkpoint(header).unwrap();
        assert_eq!(signers, vec![addr_a(), addr_b(), addr_c()]);
    }

    #[test]
    fn recently_signed_protection() {
        let snap = snapshot_with_signers(&[addr_a(), addr_b(), addr_c(), addr_d()]);
        // 4 signers: limit = 4/2 + 1 = 3
        let h1 = sealed_vote(1, addr_a(), addr_e(), true);
        let next = snap.apply(&[h1], recover_ok).unwrap();
        // a signs again at block 2 → within window (1 > 2-3) → rejected
        let h2 = sealed_vote(2, addr_a(), addr_f(), true);
        assert_eq!(next.apply(&[h2], recover_ok).unwrap_err(), CliqueError::RecentlySigned);
        // b signs block 2 (fine), then b again at block 3 → within window → rejected
        let h2b = sealed_vote(2, addr_b(), Address::ZERO, false);
        let next2 = next.apply(&[h2b], recover_ok).unwrap();
        let h3 = sealed_vote(3, addr_b(), addr_f(), true);
        assert_eq!(next2.apply(&[h3], recover_ok).unwrap_err(), CliqueError::RecentlySigned);
        // but a may sign block 3: recents{1:a,2:b}; block 3 frees recents[0]
        // (limit=3) — wait, a signed block 1, and 1 > 3-3=0 → still rejected
        let h3a = sealed_vote(3, addr_a(), Address::ZERO, false);
        assert_eq!(next2.apply(&[h3a], recover_ok).unwrap_err(), CliqueError::RecentlySigned);
    }

    #[test]
    fn signer_freed_after_window() {
        // 3 signers → limit = 2: a signs block 1, is free again at block 3
        // (block 3 removes recents[3-2=1])
        let snap = snapshot_with_signers(&[addr_a(), addr_b(), addr_c()]);
        let h1 = sealed_vote(1, addr_a(), Address::ZERO, false);
        let next = snap.apply(&[h1], recover_ok).unwrap();
        let h2 = sealed_vote(2, addr_b(), Address::ZERO, false);
        let next = next.apply(&[h2], recover_ok).unwrap(); // removes recents[0]
        let h3 = sealed_vote(3, addr_a(), Address::ZERO, false);
        assert!(next.apply(&[h3], recover_ok).is_ok());
    }

    #[test]
    fn signer_drop_via_majority() {
        let snap = snapshot_with_signers(&[addr_a(), addr_b(), addr_c()]);
        // drop a: needs 2 votes
        let headers = vec![
            sealed_vote(1, addr_b(), addr_a(), false),
            sealed_vote(2, addr_c(), addr_a(), false),
        ];
        let next = snap.apply(&headers, recover_ok).unwrap();
        assert!(!next.signers.contains(&addr_a()));
        assert_eq!(next.signers.len(), 2);
    }

    #[test]
    fn verify_seal_checks_turn_difficulty() {
        let snap = snapshot_with_signers(&[addr_a(), addr_b(), addr_c()]);
        // turn order: block N is signed in-turn by sorted_signers[N % 3] —
        // block 1 belongs to b
        let header = sealed_vote(1, addr_b(), Address::ZERO, false);
        assert!(matches!(
            snap.verify_seal_with(header.header(), 1, recover_ok),
            Ok(s) if s == addr_b()
        ));
        // in-turn signer presenting noturn difficulty → rejected
        let wrong = header_with_difficulty(1, addr_b(), Address::ZERO, false, crate::DIFF_NOTURN);
        assert_eq!(
            snap.verify_seal_with(wrong.header(), 1, recover_ok).unwrap_err(),
            CliqueError::WrongDifficulty
        );
        // non-signer address
        let rogue = sealed_vote(1, addr_d(), Address::ZERO, false);
        assert_eq!(
            snap.verify_seal_with(rogue.header(), 1, recover_ok).unwrap_err(),
            CliqueError::UnauthorizedSigner
        );
    }

    #[test]
    fn contiguity_enforced() {
        let snap = snapshot_with_signers(&[addr_a()]);
        let headers = vec![sealed_vote(2, addr_a(), Address::ZERO, false)];
        assert_eq!(snap.apply(&headers, recover_ok).unwrap_err(), CliqueError::InvalidVotingChain);
    }
}

#[cfg(test)]
mod test_util {
    use super::*;
    use alloy_primitives::address;

    pub(super) fn addr_a() -> Address {
        address!("00000000000000000000000000000000000000aa")
    }
    pub(super) fn addr_b() -> Address {
        address!("00000000000000000000000000000000000000bb")
    }
    pub(super) fn addr_c() -> Address {
        address!("00000000000000000000000000000000000000cc")
    }
    pub(super) fn addr_d() -> Address {
        address!("00000000000000000000000000000000000000dd")
    }
    pub(super) fn addr_e() -> Address {
        address!("00000000000000000000000000000000000000ee")
    }
    pub(super) fn addr_f() -> Address {
        address!("00000000000000000000000000000000000000ff")
    }

    pub(super) fn snapshot_with_signers(signers: &[Address]) -> Snapshot {
        Snapshot::new(CliqueConfig::new(10, 30000), 0, B256::ZERO, signers.to_vec())
    }

    /// Identity recovery for tests: the "signer" is encoded in the `mix_hash`? No —
    /// we use the beneficiary field as a stand-in: headers built by [`sealed_vote`]
    /// carry the signer in the extraData vanity's first byte set by convention.
    pub(super) fn recover_ok(header: &Header) -> Result<Address, CliqueError> {
        test_signer_of(header).ok_or(CliqueError::UnauthorizedSigner)
    }

    fn test_signer_of(header: &Header) -> Option<Address> {
        // Tests encode the signer as the last 20 bytes of the vanity (first 32B).
        let vanity = &header.extra_data[..EXTRA_VANITY];
        Some(Address::from_slice(&vanity[EXTRA_VANITY - 20..]))
    }

    fn header_at(number: u64, signer: Address, coinbase: Address, authorize: bool) -> SealedHeader {
        let mut vanity = [0u8; EXTRA_VANITY];
        vanity[EXTRA_VANITY - 20..].copy_from_slice(signer.as_slice());
        let header = Header {
            number,
            extra_data: vanity.into(),
            beneficiary: coinbase,
            nonce: if authorize { crate::NONCE_AUTH_VOTE } else { crate::NONCE_DROP_VOTE },
            difficulty: crate::DIFF_INTURN,
            ..Default::default()
        };
        SealedHeader::seal_slow(header)
    }

    pub(super) fn sealed_vote(number: u64, signer: Address, target: Address, authorize: bool) -> SealedHeader {
        header_at(number, signer, target, authorize)
    }

    /// A header with an explicit difficulty (for wrong-turn tests).
    pub(super) fn header_with_difficulty(
        number: u64,
        signer: Address,
        target: Address,
        authorize: bool,
        difficulty: alloy_primitives::U256,
    ) -> SealedHeader {
        let mut vanity = [0u8; EXTRA_VANITY];
        vanity[EXTRA_VANITY - 20..].copy_from_slice(signer.as_slice());
        let header = Header {
            number,
            extra_data: vanity.into(),
            beneficiary: target,
            nonce: if authorize { crate::NONCE_AUTH_VOTE } else { crate::NONCE_DROP_VOTE },
            difficulty,
            ..Default::default()
        };
        SealedHeader::seal_slow(header)
    }

    pub(super) fn sealed_checkpoint(number: u64) -> SealedHeader {
        // checkpoint: coinbase/nonce zeroed, signer list in extraData; the
        // test signer is embedded in the vanity (same convention as
        // sealed_vote) — pick a signer that didn't sign the previous block
        let mut extra: Vec<u8> = vec![0u8; EXTRA_VANITY];
        extra[EXTRA_VANITY - 20..].copy_from_slice(addr_b().as_slice());
        for addr in [addr_a(), addr_b(), addr_c()] {
            extra.extend_from_slice(addr.as_slice());
        }
        extra.extend_from_slice(&[0u8; crate::EXTRA_SEAL]);
        let header = Header {
            number,
            extra_data: extra.into(),
            beneficiary: Address::ZERO,
            nonce: crate::NONCE_DROP_VOTE,
            difficulty: crate::DIFF_INTURN,
            ..Default::default()
        };
        SealedHeader::seal_slow(header)
    }
}
