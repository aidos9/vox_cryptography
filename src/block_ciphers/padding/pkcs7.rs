use super::Padding;

pub struct PKCS7;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

impl Padding for PKCS7 {
    fn pad_block(input: &[u8], block_size: usize) -> (Vec<u8>, Option<Vec<u8>>) {
        let mut a = input.to_vec();

        if input.len() == block_size {
            return (a, Some(vec![block_size as u8; block_size]));
        } else {
            let n = (block_size - input.len()) as u8;

            for _ in input.len()..block_size {
                a.push(n);
            }

            return (a, None);
        }
    }

    fn validate_padded_block(block: &[u8]) -> Option<usize> {
        for i in 0..block[block.len() - 1] {
            if block[block.len() - 1 - i as usize] != block[block.len() - 1] {
                return None;
            }
        }

        return Some(block[block.len() - 1] as usize);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7_47_to_64_bytes() {
        let input: Vec<u8> = (0..47).into_iter().collect();
        let mut reference = input.clone();

        for _ in 0..17 {
            reference.push(17);
        }

        assert_eq!(PKCS7::pad_block(&input, 64).0, reference);
    }

    #[test]
    fn test_pkcs7_63_to_64_bytes() {
        let input: Vec<u8> = (0..63).into_iter().collect();
        let mut reference = input.clone();

        for _ in 0..1 {
            reference.push(1);
        }

        assert_eq!(PKCS7::pad_block(&input, 64).0, reference);
    }

    #[test]
    fn test_pkcs7_64_to_128_bytes() {
        let input: Vec<u8> = (0..64).into_iter().collect();
        let reference = input.clone();
        let mut alt = Vec::new();

        for _ in 0..64 {
            alt.push(64);
        }

        let out = PKCS7::pad_block(&input, 64);

        assert_eq!(out.0, reference);
        assert_eq!(out.1, Some(alt));
    }
}
