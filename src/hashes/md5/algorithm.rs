use crate::hashes::HashingAlgorithm;

use super::constants::*;

pub struct MD5 {
    hash_state: [u32; 4],
}

impl HashingAlgorithm for MD5 {
    type Chunk = [u8; 64];
    type Output = [u8; 16];

    const CHUNK_SIZE: usize = 64;
    const OUTPUT_SIZE: usize = 16;
    const LENGTH_MODULO: u128 = 0xffff_ffff_ffff_ffff;

    fn empty_chunk() -> Self::Chunk {
        return [0u8; Self::CHUNK_SIZE];
    }

    fn update(&mut self, chunk: &[u8], _bytes_processed: u128) {
        let mut msg = [0u32; 16];

        for i in 0..16 {
            msg[i] = ((chunk[4 * i] as u32) << 0)
                | ((chunk[4 * i + 1] as u32) << 8)
                | ((chunk[4 * i + 2] as u32) << 16)
                | ((chunk[4 * i + 3] as u32) << 24);
        }

        let mut working = self.hash_state.clone();

        for i in 0..64 {
            let mut f;
            let g;

            if i < 16 {
                f = (working[1] & working[2]) | (!working[1] & working[3]);
                g = i;
            } else if i < 32 {
                f = (working[3] & working[1]) | (!working[3] & working[2]);
                g = (5 * i + 1) % 16;
            } else if i < 48 {
                f = working[1] ^ working[2] ^ working[3];
                g = (3 * i + 5) % 16;
            } else {
                f = working[2] ^ (working[1] | !working[3]);
                g = (7 * i) % 16;
            }

            f = f
                .wrapping_add(working[0])
                .wrapping_add(MD5_ROUND_CONSTANTS[i])
                .wrapping_add(msg[g]);
            working[0] = working[3];
            working[3] = working[2];
            working[2] = working[1];
            working[1] = working[1].wrapping_add(f.rotate_left(MD5_ROUND_SHIFTS[i]));
        }

        for i in 0..4 {
            self.hash_state[i] = self.hash_state[i].wrapping_add(working[i]);
        }
    }

    fn finalize(mut self, partial_chunk: &[u8], total_bytes_processed: u128) -> Self::Output {
        if partial_chunk.len() == 64 {
            self.update(partial_chunk, total_bytes_processed);

            let mut chunk = [0u8; 64];
            chunk[0] = 0b1000_0000;
            chunk[56..].copy_from_slice(
                &(((total_bytes_processed * 8) % Self::LENGTH_MODULO) as u64).to_le_bytes(),
            );
            self.update(&chunk, total_bytes_processed);
        } else if partial_chunk.len() + 9 > 64 {
            let mut chunk_a = [0u8; 64];
            chunk_a[0..partial_chunk.len()].copy_from_slice(partial_chunk);
            chunk_a[partial_chunk.len()] = 0b1000_0000;

            self.update(&chunk_a, total_bytes_processed);

            let mut chunk = [0u8; 64];
            chunk[56..].copy_from_slice(
                &(((total_bytes_processed * 8) % Self::LENGTH_MODULO) as u64).to_le_bytes(),
            );

            self.update(&chunk, total_bytes_processed);
        } else {
            let mut chunk = [0u8; 64];

            chunk[0..partial_chunk.len()].copy_from_slice(partial_chunk);
            chunk[partial_chunk.len()] = 0b1000_0000;
            chunk[56..].copy_from_slice(
                &(((total_bytes_processed * 8) % Self::LENGTH_MODULO) as u64).to_le_bytes(),
            );

            self.update(&chunk, total_bytes_processed);
        }

        let mut output = [0u8; 16];

        for (m, b) in self
            .hash_state
            .into_iter()
            .enumerate()
            .map(|(i, n)| (i * 4, n.to_le_bytes()))
        {
            for i in 0..4 {
                output[m + i] = b[i];
            }
        }

        return output;
    }
}

impl Default for MD5 {
    fn default() -> Self {
        return Self {
            hash_state: MD5_H_STATE,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_md5_lazy_dog() {
        let input = b"The quick brown fox jumps over the lazy dog";

        assert_eq!(
            MD5::hash(input),
            [
                0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4,
                0x19, 0xd6
            ]
        );
    }

    #[test]
    fn test_md5_lazy_dog_fullstop() {
        let input = b"The quick brown fox jumps over the lazy dog.";

        assert_eq!(
            MD5::hash(input),
            [
                0xe4, 0xd9, 0x09, 0xc2, 0x90, 0xd0, 0xfb, 0x1c, 0xa0, 0x68, 0xff, 0xad, 0xdf, 0x22,
                0xcb, 0xd0
            ]
        );
    }

    #[test]
    fn test_md5_empty() {
        assert_eq!(
            MD5::hash(&[]),
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
                0x42, 0x7e
            ]
        );
    }
}
