#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

pub mod block_ciphers;
pub mod error;
pub mod hashes;
#[cfg(any(feature = "alloc", feature = "std"))]
pub mod hmac;
#[cfg(any(feature = "alloc", feature = "std"))]
pub mod kdf;
pub mod random;
