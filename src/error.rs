use core::fmt::{self, Debug, Display};
#[cfg(feature = "std")]
use std::error::Error;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum VCryptoError {
    InvalidKeyLengthLarger { key_length: usize, max: usize },
    InvalidKeyLengthSmaller { key_length: usize, min: usize },
    InvalidBlockSize { block_size: usize, expected: usize },
    InvalidKey,
    InvalidPadding,
    InvalidInput,
}

#[cfg(feature = "std")]
impl Error for VCryptoError {}

impl Display for VCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return match self {
            VCryptoError::InvalidKeyLengthLarger {
                key_length: _,
                max: _,
            } => write!(f, "invalid key length"),
            VCryptoError::InvalidKeyLengthSmaller {
                key_length: _,
                min: _,
            } => write!(f, "invalid key length"),
            VCryptoError::InvalidBlockSize {
                block_size: _,
                expected: _,
            } => write!(f, "invalid block size"),
            VCryptoError::InvalidKey => write!(f, "invalid key"),
            VCryptoError::InvalidPadding => write!(f, "invalid padding"),
            VCryptoError::InvalidInput => write!(f, "invalid input"),
        };
    }
}

impl Debug for VCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return match self {
            VCryptoError::InvalidKeyLengthLarger { key_length, max } => write!(
                f,
                "invalid key length ({}), key length should be smaller than {}",
                key_length, max
            ),
            VCryptoError::InvalidKeyLengthSmaller { key_length, min } => write!(
                f,
                "invalid key length ({}), key length should be greater than {}",
                key_length, min
            ),
            VCryptoError::InvalidBlockSize {
                block_size,
                expected,
            } => write!(
                f,
                "invalid block size ({}), the block should contain {} bytes",
                block_size, expected
            ),
            VCryptoError::InvalidKey => write!(f, "invalid key"),
            VCryptoError::InvalidPadding => write!(f, "invalid padding"),
            VCryptoError::InvalidInput => write!(f, "invalid input"),
        };
    }
}
