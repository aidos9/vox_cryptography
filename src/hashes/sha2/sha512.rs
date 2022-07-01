use super::constants::{SHA384_H_VALUES, SHA512_H_VALUES, SHA512_ROUND_CONSTANTS};
use crate::hashes::HashingAlgorithm;

use core::default::Default;

use byteorder::{BigEndian, ByteOrder};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SHA384 {
    internal_hasher: SHA512,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SHA512 {
    hash_state: [u64; 8],
}

fn copy_1024bit_chunk(chunk: &[u8], destination: &mut [u64]) {
    for i in 0..16 {
        destination[i] = BigEndian::read_u64(&chunk[i * 8..(i + 1) * 8])
    }
}

impl HashingAlgorithm for SHA384 {
    type Chunk = <SHA512 as HashingAlgorithm>::Chunk;
    type Output = [u8; 48];

    const CHUNK_SIZE: usize = <SHA512 as HashingAlgorithm>::CHUNK_SIZE;
    const OUTPUT_SIZE: usize = 48;
    const LENGTH_MODULO: u128 = <SHA512 as HashingAlgorithm>::LENGTH_MODULO;

    fn empty_chunk() -> Self::Chunk {
        return <SHA512 as HashingAlgorithm>::empty_chunk();
    }

    fn update(&mut self, chunk: &[u8]) {
        self.internal_hasher.update(chunk);
    }

    fn finalize(self, partial_chunk: &[u8], total_bytes_processed: u128) -> Self::Output {
        let output = self
            .internal_hasher
            .finalize(partial_chunk, total_bytes_processed);

        let mut truncated = [0u8; 48];

        truncated.copy_from_slice(&output[0..48]);

        return truncated;
    }
}

impl Default for SHA384 {
    fn default() -> Self {
        return Self {
            internal_hasher: SHA512 {
                hash_state: SHA384_H_VALUES,
            },
        };
    }
}

impl HashingAlgorithm for SHA512 {
    type Chunk = [u8; 128];
    type Output = [u8; 64];

    const CHUNK_SIZE: usize = 128;
    const OUTPUT_SIZE: usize = 64;
    const LENGTH_MODULO: u128 = u128::MAX;

    fn empty_chunk() -> Self::Chunk {
        return [0u8; 128];
    }

    fn update(&mut self, chunk: &[u8]) {
        let mut schedule = [0u64; 80];

        copy_1024bit_chunk(chunk, &mut schedule);

        for i in 16..80 {
            let s0 = schedule[i - 15].rotate_right(1)
                ^ schedule[i - 15].rotate_right(8)
                ^ (schedule[i - 15] >> 7);

            let s1 = schedule[i - 2].rotate_right(19)
                ^ schedule[i - 2].rotate_right(61)
                ^ (schedule[i - 2] >> 6);

            schedule[i] = schedule[i - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[i - 7])
                .wrapping_add(s1);
        }

        let mut working = self.hash_state.clone();

        for i in 0..80 {
            let s1 = working[4].rotate_right(14)
                ^ working[4].rotate_right(18)
                ^ working[4].rotate_right(41);

            let ch = (working[4] & working[5]) ^ (!working[4] & working[6]);

            let temp1 = working[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA512_ROUND_CONSTANTS[i])
                .wrapping_add(schedule[i]);

            let s0 = working[0].rotate_right(28)
                ^ working[0].rotate_right(34)
                ^ working[0].rotate_right(39);

            let maj =
                (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);

            let temp2 = s0.wrapping_add(maj);

            working[7] = working[6];
            working[6] = working[5];
            working[5] = working[4];
            working[4] = working[3].wrapping_add(temp1);
            working[3] = working[2];
            working[2] = working[1];
            working[1] = working[0];
            working[0] = temp1.wrapping_add(temp2);
        }

        for i in 0..8 {
            self.hash_state[i] = self.hash_state[i].wrapping_add(working[i]);
        }
    }

    fn finalize(mut self, partial_chunk: &[u8], total_bytes_processed: u128) -> Self::Output {
        // Check if we need 2 blocks to make a multiple of 1024 bits
        if partial_chunk.len() == Self::CHUNK_SIZE {
            self.update(partial_chunk);

            let mut chunk = [0u8; Self::CHUNK_SIZE];
            chunk[0] = 0b1000_0000;
            chunk[Self::CHUNK_SIZE - 16..]
                .copy_from_slice(&(total_bytes_processed * 8).to_be_bytes());
            self.update(&chunk);
        } else if partial_chunk.len() + 9 > Self::CHUNK_SIZE {
            let mut chunk_a = [0u8; Self::CHUNK_SIZE];
            chunk_a[0..partial_chunk.len()].copy_from_slice(partial_chunk);
            chunk_a[partial_chunk.len()] = 0b1000_0000;

            self.update(&chunk_a);

            let mut chunk = [0u8; Self::CHUNK_SIZE];
            chunk[Self::CHUNK_SIZE - 16..]
                .copy_from_slice(&(total_bytes_processed * 8).to_be_bytes());

            self.update(&chunk);
        } else {
            let mut chunk = [0u8; Self::CHUNK_SIZE];

            chunk[0..partial_chunk.len()].copy_from_slice(partial_chunk);
            chunk[partial_chunk.len()] = 0b1000_0000;
            chunk[Self::CHUNK_SIZE - 16..]
                .copy_from_slice(&(total_bytes_processed * 8).to_be_bytes());

            self.update(&chunk);
        }

        let mut output = [0u8; 64];

        for (m, b) in self
            .hash_state
            .into_iter()
            .enumerate()
            .map(|(i, n)| (i * 8, n.to_be_bytes()))
        {
            for i in 0..8 {
                output[m + i] = b[i];
            }
        }

        return output;
    }
}

impl Default for SHA512 {
    fn default() -> Self {
        return Self {
            hash_state: SHA512_H_VALUES,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_sha512_empty() {
        assert_eq!(
            SHA512::hash(&[]),
            [
                0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
                0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
                0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
                0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
                0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
            ]
        )
    }

    #[test]
    fn test_sha512_abc() {
        let input = b"abc";

        assert_eq!(
            SHA512::hash(input),
            [
                0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
                0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
                0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
                0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
                0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
            ]
        )
    }

    #[test]
    fn test_sha512_large_input() {
        let input = b"this test should be longer than one block and a bit longer than 2 blocks. This means it must be 3 or more blocks, how about that! Well this last bit of text is just filling for space :)";

        assert_eq!(
            SHA512::hash(input),
            [
                0x3b, 0x1b, 0x7a, 0x53, 0x66, 0x58, 0x30, 0x2c, 0xc8, 0x75, 0x01, 0x93, 0xf9, 0xe3,
                0xe1, 0x3d, 0x4a, 0xd3, 0x7f, 0x8d, 0x34, 0x30, 0xd7, 0xbc, 0x86, 0x0a, 0x65, 0xe5,
                0xba, 0x0e, 0x67, 0x39, 0xd0, 0xcb, 0x4e, 0x67, 0x9f, 0xb4, 0xb5, 0xb5, 0x26, 0xf7,
                0x7d, 0x90, 0x9a, 0xa1, 0x30, 0x03, 0x20, 0x9d, 0xc0, 0xa0, 0x77, 0xab, 0x30, 0xa3,
                0x85, 0x36, 0x19, 0x31, 0xf7, 0x23, 0xa3, 0xd7
            ]
        )
    }

    #[test]
    fn test_sha384_abc() {
        let input = b"abc";

        assert_eq!(
            SHA384::hash(input),
            [
                0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6,
                0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a,
                0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba,
                0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7
            ]
        )
    }

    #[test]
    fn test_sha384_long_input() {
        let input = b"this test should be longer than one block and a bit longer than 2 blocks. This means it must be 3 or more blocks, how about that! Well this last bit of text is just filling for space :)";

        assert_eq!(
            SHA384::hash(input),
            [
                0xc2, 0x3f, 0x3a, 0x6a, 0x53, 0x1b, 0x50, 0xb5, 0xe2, 0xb3, 0xd9, 0xf6, 0x55, 0x48,
                0x88, 0x33, 0x83, 0x11, 0xb1, 0x6d, 0xa0, 0x0f, 0xcb, 0x88, 0x12, 0xa1, 0x05, 0x75,
                0xa9, 0x69, 0x00, 0xbf, 0x3c, 0x6d, 0x8c, 0x79, 0x7e, 0x99, 0x14, 0xc8, 0xeb, 0xe8,
                0x63, 0x8b, 0xfe, 0x36, 0xb3, 0xbb
            ]
        )
    }
}
