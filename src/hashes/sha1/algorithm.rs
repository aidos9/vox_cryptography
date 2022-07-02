use super::constants::*;
use crate::hashes::HashingAlgorithm;

use byteorder::{BigEndian, ByteOrder};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SHA1 {
    hash_state: [u32; 5],
}

fn copy_512bit_chunk(chunk: &[u8], destination: &mut [u32]) {
    for i in 0..16 {
        destination[i] = BigEndian::read_u32(&chunk[i * 4..i * 4 + 4]);
    }
}

impl HashingAlgorithm for SHA1 {
    type Chunk = [u8; 64];
    type Output = [u8; 20];

    const CHUNK_SIZE: usize = 64;
    const OUTPUT_SIZE: usize = 20;
    const LENGTH_MODULO: u128 = 0xFFFF_FFFF_FFFF_FFFF;

    fn empty_chunk() -> Self::Chunk {
        return [0u8; Self::CHUNK_SIZE];
    }

    fn update(&mut self, chunk: &[u8], _bytes_processed: u128) {
        let mut schedule = [0u32; 80];

        copy_512bit_chunk(chunk, &mut schedule);

        for i in 16..80 {
            schedule[i] = (schedule[i - 3] ^ schedule[i - 8] ^ schedule[i - 14] ^ schedule[i - 16])
                .rotate_left(1);
        }

        let mut working = self.hash_state.clone();

        for i in 0..80 {
            let (k, f);

            if i < 20 {
                f = (working[1] & working[2]) | (!working[1] & working[3]);
                k = SHA1_K_VALUES[0];
            } else if i < 40 {
                f = working[1] ^ working[2] ^ working[3];
                k = SHA1_K_VALUES[1];
            } else if i < 60 {
                f = (working[1] & working[2])
                    | (working[1] & working[3])
                    | (working[2] & working[3]);
                k = SHA1_K_VALUES[2];
            } else {
                f = working[1] ^ working[2] ^ working[3];
                k = SHA1_K_VALUES[3];
            }

            let temp = working[0]
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(working[4])
                .wrapping_add(k)
                .wrapping_add(schedule[i]);

            working[4] = working[3];
            working[3] = working[2];
            working[2] = working[1].rotate_left(30);
            working[1] = working[0];
            working[0] = temp;
        }

        for i in 0..5 {
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

        let mut output = [0u8; 20];

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

impl Default for SHA1 {
    fn default() -> Self {
        return Self {
            hash_state: SHA1_H_VALUES,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_sha1_empty() {
        assert_eq!(
            SHA1::hash(&[]),
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
            ]
        );
    }

    #[test]
    fn test_sha1_lazy_dog() {
        assert_eq!(
            SHA1::hash(b"The quick brown fox jumps over the lazy dog"),
            [
                0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76,
                0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12
            ]
        );
    }

    #[test]
    fn test_sha1_lazy_cog() {
        assert_eq!(
            SHA1::hash(b"The quick brown fox jumps over the lazy cog"),
            [
                0xde, 0x9f, 0x2c, 0x7f, 0xd2, 0x5e, 0x1b, 0x3a, 0xfa, 0xd3, 0xe8, 0x5a, 0x0b, 0xd1,
                0x7d, 0x9b, 0x10, 0x0d, 0xb4, 0xb3
            ]
        );
    }
}
