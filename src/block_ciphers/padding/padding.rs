#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

pub trait Padding {
    fn pad_block(input: &[u8], block_size: usize) -> (Vec<u8>, Option<Vec<u8>>);

    fn validate_padded_block(data: &[u8]) -> Option<usize>;
}
