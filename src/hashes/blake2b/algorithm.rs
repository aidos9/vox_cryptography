use super::constants::*;
use crate::hashes::HashingAlgorithm;

use core::cmp::min;

pub struct BLAKE2bBuilder {
    key: Option<[u8; 128]>,
    key_len: u8,
    output_len: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BLAKE2b {
    hash_state: [u64; 8],
    output_len: u8,
    key_provided: bool,
}

impl BLAKE2bBuilder {
    pub fn new() -> Self {
        return Self {
            key: None,
            key_len: 0,
            output_len: 0,
        };
    }

    pub fn with_key_slice(mut self, key: &[u8]) -> Self {
        let n = min(64, key.len());
        let mut k = [0u8; 128];
        k[..n].copy_from_slice(&key[..n]);

        self.key = Some(k);

        return self;
    }

    pub fn with_output_len(mut self, output_len: u8) -> Self {
        if output_len < 64 || output_len > 1 {
            panic!("Invalid BLAKE2b output length");
        }

        self.output_len = output_len;

        return self;
    }

    pub fn build(self) -> BLAKE2b {
        return BLAKE2b {
            hash_state: BLAKE2B_IV,
            output_len: self.output_len,
            key_provided: self.key.is_some(),
        }
        .initialize(self.key, self.key_len as u64);
    }
}

impl BLAKE2b {
    pub fn builder() -> BLAKE2bBuilder {
        return BLAKE2bBuilder::new();
    }

    fn initialize(mut self, key: Option<[u8; 128]>, key_len: u64) -> Self {
        // self.hash_state[0] ^= ((0x0101 as u64) << 4) | (key_len << 2) | (self.output_len as u64);
        self.hash_state[0] =
            self.hash_state[0] ^ 0x01010000 ^ (key_len << 8) ^ self.output_len as u64;

        if let Some(k) = key {
            self.update(&k, 0);
        }

        return self;
    }

    fn compress(&mut self, chunk: &[u8], bytes_processed: u128, final_block: bool) {
        let tbp;

        if self.key_provided {
            tbp = bytes_processed + 128;
        } else {
            tbp = bytes_processed;
        }

        let mut v = [0u64; 16];
        v[0..8].copy_from_slice(&self.hash_state);
        v[8..].copy_from_slice(&BLAKE2B_IV);

        v[12] ^= (tbp.to_le() & 0xffff_ffff_ffff_ffff) as u64;
        v[13] ^= (tbp.to_le() >> 64) as u64;

        if final_block {
            v[14] ^= 0xffff_ffff_ffff_ffff;
        }

        let mut m = [0u64; 16];

        for i in 0..16 {
            m[i] = u64::from_le(
                ((chunk[i * 8 + 0] as u64) << 0)
                    | ((chunk[i * 8 + 1] as u64) << 8)
                    | ((chunk[i * 8 + 2] as u64) << 16)
                    | ((chunk[i * 8 + 3] as u64) << 24)
                    | ((chunk[i * 8 + 4] as u64) << 32)
                    | ((chunk[i * 8 + 5] as u64) << 40)
                    | ((chunk[i * 8 + 6] as u64) << 48)
                    | ((chunk[i * 8 + 7] as u64) << 56),
            );
        }

        for i in 0..12 {
            let s = BLAKE2B_SCHEDULE[i % 10];

            Self::mix(&mut v, 0, 4, 8, 12, m[s[0] as usize], m[s[1] as usize]);
            Self::mix(&mut v, 1, 5, 9, 13, m[s[2] as usize], m[s[3] as usize]);
            Self::mix(&mut v, 2, 6, 10, 14, m[s[4] as usize], m[s[5] as usize]);
            Self::mix(&mut v, 3, 7, 11, 15, m[s[6] as usize], m[s[7] as usize]);

            Self::mix(&mut v, 0, 5, 10, 15, m[s[8] as usize], m[s[9] as usize]);
            Self::mix(&mut v, 1, 6, 11, 12, m[s[10] as usize], m[s[11] as usize]);
            Self::mix(&mut v, 2, 7, 8, 13, m[s[12] as usize], m[s[13] as usize]);
            Self::mix(&mut v, 3, 4, 9, 14, m[s[14] as usize], m[s[15] as usize]);
        }

        for i in 0..8 {
            self.hash_state[i] = self.hash_state[i] ^ v[i] ^ v[i + 8];
        }
    }

    #[inline]
    fn mix(working: &mut [u64], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
        working[a] = working[a].wrapping_add(working[b]).wrapping_add(x);
        working[d] = (working[d] ^ working[a]).rotate_right(32);

        working[c] = working[c].wrapping_add(working[d]);
        working[b] = (working[b] ^ working[c]).rotate_right(24);

        working[a] = working[a].wrapping_add(working[b]).wrapping_add(y);
        working[d] = (working[d] ^ working[a]).rotate_right(16);

        working[c] = working[c].wrapping_add(working[d]);
        working[b] = (working[b] ^ working[c]).rotate_right(63);
    }
}

impl HashingAlgorithm for BLAKE2b {
    type Chunk = [u8; 128];

    type Output = [u8; 64];

    const CHUNK_SIZE: usize = 128;

    const OUTPUT_SIZE: usize = 64;

    const LENGTH_MODULO: u128 = u128::MAX;

    fn empty_chunk() -> Self::Chunk {
        return [0u8; Self::CHUNK_SIZE];
    }

    fn update(&mut self, chunk: &[u8], bytes_processed: u128) {
        self.compress(chunk, bytes_processed, false);
    }

    fn finalize(mut self, partial_chunk: &[u8], total_bytes_processed: u128) -> Self::Output {
        let mut final_chunk = [0u8; 128];
        final_chunk[0..partial_chunk.len()].copy_from_slice(partial_chunk);

        self.compress(&final_chunk, total_bytes_processed, true);

        let mut max_output = [0u8; 64];

        for (i, b) in self
            .hash_state
            .into_iter()
            .enumerate()
            .map(|(i, n)| (i * 8, n.to_le_bytes()))
        {
            max_output[i..i + 8].copy_from_slice(&b);
        }

        return max_output;
    }
}

impl Default for BLAKE2b {
    fn default() -> Self {
        return Self {
            hash_state: BLAKE2B_IV,
            output_len: 64,
            key_provided: false,
        }
        .initialize(None, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_blake2b_512_empty() {
        assert_eq!(
            BLAKE2b::hash(&[]),
            [
                0x78, 0x6a, 0x02, 0xf7, 0x42, 0x01, 0x59, 0x03, 0xc6, 0xc6, 0xfd, 0x85, 0x25, 0x52,
                0xd2, 0x72, 0x91, 0x2f, 0x47, 0x40, 0xe1, 0x58, 0x47, 0x61, 0x8a, 0x86, 0xe2, 0x17,
                0xf7, 0x1f, 0x54, 0x19, 0xd2, 0x5e, 0x10, 0x31, 0xaf, 0xee, 0x58, 0x53, 0x13, 0x89,
                0x64, 0x44, 0x93, 0x4e, 0xb0, 0x4b, 0x90, 0x3a, 0x68, 0x5b, 0x14, 0x48, 0xb7, 0x55,
                0xd5, 0x6f, 0x70, 0x1a, 0xfe, 0x9b, 0xe2, 0xce
            ]
        );
    }

    #[test]
    fn test_blake2b_512_abc() {
        assert_eq!(
            BLAKE2b::hash(b"abc"),
            [
                0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d, 0x6a, 0x27, 0x97, 0xb6, 0x9f, 0x12,
                0xf6, 0xe9, 0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a, 0xc4, 0xb7, 0x4b, 0x12, 0xbb, 0x6f,
                0xdb, 0xff, 0xa2, 0xd1, 0x7d, 0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d, 0xc2, 0x52,
                0xd5, 0xde, 0x45, 0x33, 0xcc, 0x95, 0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92, 0x5a,
                0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23
            ]
        );
    }

    #[test]
    fn test_blake2b_large_input() {
        let input = b"this test should be longer than one block and a bit longer than 2 blocks. This means it must be 3 or more blocks, how about that! Well this last bit of text is just filling for space :)";

        assert_eq!(
            BLAKE2b::hash(input),
            [
                0x15, 0xe9, 0xef, 0x0a, 0x7a, 0xd5, 0x94, 0x8a, 0x87, 0x6c, 0xae, 0xac, 0x7f, 0x6d,
                0x53, 0x23, 0x23, 0x6d, 0x09, 0xc9, 0x86, 0xbc, 0x97, 0x87, 0x8b, 0xc7, 0x43, 0xa0,
                0x62, 0xca, 0xe1, 0x93, 0x47, 0x91, 0xf1, 0xd0, 0x67, 0x0d, 0x93, 0x50, 0x3d, 0x60,
                0x14, 0x09, 0xd8, 0x87, 0xd3, 0xb5, 0x2c, 0xe3, 0x61, 0x81, 0xa5, 0xf8, 0xfe, 0xe1,
                0xbd, 0x4e, 0x44, 0x84, 0x85, 0x91, 0xcc, 0x14
            ]
        )
    }
}
