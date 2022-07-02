use byteorder::{BigEndian, ByteOrder};

use super::constants::{SHA224_H_VALUES, SHA256_H_VALUES, SHA256_ROUND_CONSTANTS};
use crate::hashes::HashingAlgorithm;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SHA224 {
    internal_hasher: SHA256,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SHA256 {
    hash_state: [u32; 8],
}

fn copy_512bit_chunk(chunk: &[u8], destination: &mut [u32]) {
    for i in 0..16 {
        destination[i] = BigEndian::read_u32(&chunk[i * 4..i * 4 + 4]);
    }
}

impl HashingAlgorithm for SHA224 {
    type Chunk = <SHA256 as HashingAlgorithm>::Chunk;
    type Output = [u8; 28];

    const CHUNK_SIZE: usize = <SHA256 as HashingAlgorithm>::CHUNK_SIZE;
    const OUTPUT_SIZE: usize = 28;
    const LENGTH_MODULO: u128 = <SHA256 as HashingAlgorithm>::LENGTH_MODULO;

    fn empty_chunk() -> Self::Chunk {
        return <SHA256 as HashingAlgorithm>::empty_chunk();
    }

    fn update(&mut self, chunk: &[u8], bytes_processed: u128) {
        self.internal_hasher.update(chunk, bytes_processed);
    }

    fn finalize(self, partial_chunk: &[u8], total_bytes_processed: u128) -> Self::Output {
        let output = self
            .internal_hasher
            .finalize(partial_chunk, total_bytes_processed);

        let mut truncated = [0u8; 28];

        truncated.copy_from_slice(&output[0..28]);

        return truncated;
    }
}

impl Default for SHA224 {
    fn default() -> Self {
        return Self {
            internal_hasher: SHA256 {
                hash_state: SHA224_H_VALUES,
            },
        };
    }
}

impl HashingAlgorithm for SHA256 {
    type Chunk = [u8; 64];
    type Output = [u8; 32];

    const CHUNK_SIZE: usize = 64;
    const OUTPUT_SIZE: usize = 32;
    const LENGTH_MODULO: u128 = 0xFFFF_FFFF_FFFF_FFFF;

    fn empty_chunk() -> Self::Chunk {
        return [0u8; 64];
    }

    fn update(&mut self, chunk: &[u8], _bytes_processed: u128) {
        let mut schedule = [0u32; 64];

        copy_512bit_chunk(chunk, &mut schedule);

        for i in 16..64 {
            let s0 = schedule[i - 15].rotate_right(7)
                ^ schedule[i - 15].rotate_right(18)
                ^ (schedule[i - 15] >> 3);

            let s1 = schedule[i - 2].rotate_right(17)
                ^ schedule[i - 2].rotate_right(19)
                ^ (schedule[i - 2] >> 10);

            schedule[i] = schedule[i - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[i - 7])
                .wrapping_add(s1);
        }

        let mut working = self.hash_state.clone();

        for i in 0..64 {
            let s1 = working[4].rotate_right(6)
                ^ working[4].rotate_right(11)
                ^ working[4].rotate_right(25);

            let ch = (working[4] & working[5]) ^ (!working[4] & working[6]);

            let temp1 = working[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_ROUND_CONSTANTS[i])
                .wrapping_add(schedule[i]);

            let s0 = working[0].rotate_right(2)
                ^ working[0].rotate_right(13)
                ^ working[0].rotate_right(22);

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
        // Check if we need 2 blocks to make a multiple of 512 bits
        if partial_chunk.len() == 64 {
            self.update(partial_chunk, total_bytes_processed);

            let mut chunk = [0u8; 64];
            chunk[0] = 0b1000_0000;
            chunk[56..].copy_from_slice(
                &(((total_bytes_processed * 8) % Self::LENGTH_MODULO) as u64).to_be_bytes(),
            );
            self.update(&chunk, total_bytes_processed);
        } else if partial_chunk.len() + 9 > 64 {
            let mut chunk_a = [0u8; 64];
            chunk_a[0..partial_chunk.len()].copy_from_slice(partial_chunk);
            chunk_a[partial_chunk.len()] = 0b1000_0000;

            self.update(&chunk_a, total_bytes_processed);

            let mut chunk = [0u8; 64];
            chunk[56..].copy_from_slice(
                &(((total_bytes_processed * 8) % Self::LENGTH_MODULO) as u64).to_be_bytes(),
            );

            self.update(&chunk, total_bytes_processed);
        } else {
            let mut chunk = [0u8; 64];

            chunk[0..partial_chunk.len()].copy_from_slice(partial_chunk);
            chunk[partial_chunk.len()] = 0b1000_0000;
            chunk[56..].copy_from_slice(
                &(((total_bytes_processed * 8) % Self::LENGTH_MODULO) as u64).to_be_bytes(),
            );

            self.update(&chunk, total_bytes_processed);
        }

        let mut output = [0u8; 32];

        for (m, b) in self
            .hash_state
            .into_iter()
            .enumerate()
            .map(|(i, n)| (i * 4, n.to_be_bytes()))
        {
            for i in 0..4 {
                output[m + i] = b[i];
            }
        }

        return output;
    }
}

impl Default for SHA256 {
    fn default() -> Self {
        return Self {
            hash_state: SHA256_H_VALUES,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_sha224_empty() {
        let input = b"";

        assert_eq!(
            SHA224::hash(input),
            [
                0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47, 0x61, 0x02, 0xbb, 0x28, 0x82,
                0x34, 0xc4, 0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3, 0xe4, 0x2f
            ]
        )
    }

    #[test]
    fn test_sha224_abc() {
        let input = b"abc";

        assert_eq!(
            SHA224::hash(input),
            [
                0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
                0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7
            ]
        )
    }

    #[test]
    fn test_sha256_empty() {
        assert_eq!(
            SHA256::hash(&[]),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        )
    }

    #[test]
    fn test_sha256_abc() {
        let input = b"abc";

        assert_eq!(
            SHA256::hash(input),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        )
    }

    #[test]
    fn test_sha256_two_blocks() {
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

        assert_eq!(
            SHA256::hash(input),
            [
                0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
                0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
                0x19, 0xdb, 0x06, 0xc1
            ]
        )
    }

    #[test]
    fn test_sha256_large_input() {
        let input = b"this test should be longer than one block and a bit longer than 2 blocks. This means it must be 3 or more blocks, how about that! Well this last bit of text is just filling for space :)";

        assert_eq!(
            SHA256::hash(input),
            [
                0x19, 0xaa, 0x42, 0xf8, 0x11, 0x02, 0x8f, 0x88, 0xb7, 0x8c, 0x7d, 0x5f, 0x63, 0xd7,
                0x63, 0x17, 0x17, 0xc8, 0x2d, 0xba, 0x59, 0x94, 0x42, 0x28, 0xee, 0xf7, 0x05, 0x18,
                0x0c, 0x1b, 0xc1, 0x73
            ]
        )
    }

    #[test]
    fn test_sha256_extra_large_input() {
        let input_str = std::iter::repeat("a").take(1_000_000).collect::<String>();
        let input = input_str.as_bytes();

        assert_eq!(
            SHA256::hash(input),
            [
                0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7,
                0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc,
                0xc7, 0x11, 0x2c, 0xd0
            ]
        )
    }
}
