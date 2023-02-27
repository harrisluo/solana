use thiserror::Error;

/// The `RemoteKeypairMedium` trait declares operations that all remote keypair
/// storage media must support. These operations allow keygen tools to safely
/// generate a Solana-compatible keypair on the medium.
pub trait RemoteKeypairMedium {
    /// Fallibly determines if the remote storage already contains a keypair
    fn has_existing_keypair(&self) -> Result<bool, RemoteKeypairMediumError>;

    // Fallibly generates an ed25519 signing keypair directly on the medium
    fn generate_keypair(&self) -> Result<(), RemoteKeypairMediumError>;
}

#[derive(Debug, Error)]
pub enum RemoteKeypairMediumError {
    #[error("custom error: {0}")]
    Custom(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("no device found")]
    NoDeviceFound,

    #[error("{0}")]
    UserCancel(String),

    #[error("unrecognized keypair type: {0}")]
    UnrecognizedType(String),

    // Remote keypair-specific errors
    #[error("OpenPGP card error: {0}")]
    OpenpgpCardError(#[from] openpgp_card::Error),
}
