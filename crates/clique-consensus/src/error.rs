use core::fmt;

/// Clique consensus errors — ported from geth `consensus/clique` error list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliqueError {
    /// The genesis block cannot be sealed / seal-verified.
    UnknownBlock,
    /// A checkpoint (epoch transition) block has a beneficiary set to non-zero.
    InvalidCheckpointBeneficiary,
    /// The vote nonce is neither `0x00..0` nor `0xff..f`.
    InvalidVote,
    /// A checkpoint block has a vote nonce set to non-zeroes.
    InvalidCheckpointVote,
    /// extraData is shorter than the 32-byte vanity prefix.
    MissingVanity,
    /// extraData does not end with the 65-byte signature.
    MissingSignature,
    /// A non-checkpoint block contains a signer list in extraData.
    ExtraSigners,
    /// A checkpoint block's signer list is not a multiple of 20 bytes.
    InvalidCheckpointSigners,
    /// A checkpoint block's signer list differs from the locally computed one.
    MismatchingCheckpointSigners,
    /// The block's mix digest is non-zero.
    InvalidMixDigest,
    /// The block contains a non-empty uncle hash.
    InvalidUncleHash,
    /// The block's difficulty is neither 1 nor 2.
    InvalidDifficulty,
    /// The block's difficulty does not match the signer's turn.
    WrongDifficulty,
    /// The block's timestamp is lower than parent timestamp + period.
    InvalidTimestamp,
    /// Out-of-range or non-contiguous headers for vote replay.
    InvalidVotingChain,
    /// The header was signed by a non-authorized entity.
    UnauthorizedSigner,
    /// The signer already signed a recent block within the protection window.
    RecentlySigned,
    /// The block's timestamp is in the future.
    FutureBlock,
    /// An ancestor needed to reconstruct the vote snapshot is unavailable.
    UnknownAncestor,
    /// secp256k1 signature recovery failed.
    InvalidSignature(String),
}

impl fmt::Display for CliqueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownBlock => write!(f, "unknown block"),
            Self::InvalidCheckpointBeneficiary => write!(f, "beneficiary in checkpoint block non-zero"),
            Self::InvalidVote => write!(f, "vote nonce not 0x00..0 or 0xff..f"),
            Self::InvalidCheckpointVote => write!(f, "vote nonce in checkpoint block non-zero"),
            Self::MissingVanity => write!(f, "extra-data 32 byte vanity prefix missing"),
            Self::MissingSignature => write!(f, "extra-data 65 byte signature suffix missing"),
            Self::ExtraSigners => write!(f, "non-checkpoint block contains extra signer list"),
            Self::InvalidCheckpointSigners => write!(f, "invalid signer list on checkpoint block"),
            Self::MismatchingCheckpointSigners => write!(f, "mismatching signer list on checkpoint block"),
            Self::InvalidMixDigest => write!(f, "non-zero mix digest"),
            Self::InvalidUncleHash => write!(f, "non empty uncle hash"),
            Self::InvalidDifficulty => write!(f, "invalid difficulty"),
            Self::WrongDifficulty => write!(f, "wrong difficulty"),
            Self::InvalidTimestamp => write!(f, "invalid timestamp"),
            Self::InvalidVotingChain => write!(f, "invalid voting chain"),
            Self::UnauthorizedSigner => write!(f, "unauthorized signer"),
            Self::RecentlySigned => write!(f, "recently signed"),
            Self::FutureBlock => write!(f, "block timestamp is in the future"),
            Self::UnknownAncestor => write!(f, "unknown ancestor"),
            Self::InvalidSignature(err) => write!(f, "invalid signature: {err}"),
        }
    }
}

impl core::error::Error for CliqueError {}
