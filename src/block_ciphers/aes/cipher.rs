use crate::block_ciphers::BlockCipher;

use super::constants::{INV_S_BOX, S_BOX};
use super::AESKey;

pub struct AES {
    // Stored in column major order, i.e. each sub array is a column
    state: [[u8; 4]; 4],
    // round_keys: [u32; ROUND_WORDS],
    key: AESKey,
}

impl AES {
    fn flattened_state(self) -> [u8; 16] {
        let mut output = [0u8; 16];

        for i in 0..4 {
            output[i * 4] = self.state[i][0];
            output[i * 4 + 1] = self.state[i][1];
            output[i * 4 + 2] = self.state[i][2];
            output[i * 4 + 3] = self.state[i][3];
        }

        return output;
    }

    fn encryption_round(&mut self, i: u16) {
        self.sub_bytes();
        self.shift_rows();
        self.mix_columns();
        self.add_round_key(i);
    }

    fn decryption_round(&mut self, i: u16) {
        self.add_round_key(i);
        self.inv_mix_columns();
        self.inv_shift_rows();
        self.inv_sub_bytes();
    }

    fn add_round_key(&mut self, round: u16) {
        for i in 0..4 {
            let key_word = self.key.get_round_key_word(round as usize * 4 + i);

            self.state[i][0] = self.state[i][0] ^ ((key_word >> 24) & 0xff) as u8;
            self.state[i][1] = self.state[i][1] ^ ((key_word >> 16) & 0xff) as u8;
            self.state[i][2] = self.state[i][2] ^ ((key_word >> 8) & 0xff) as u8;
            self.state[i][3] = self.state[i][3] ^ (key_word & 0xff) as u8;
        }
    }

    fn sub_bytes(&mut self) {
        for i in 0..4 {
            self.state[i][0] = S_BOX[self.state[i][0] as usize];
            self.state[i][1] = S_BOX[self.state[i][1] as usize];
            self.state[i][2] = S_BOX[self.state[i][2] as usize];
            self.state[i][3] = S_BOX[self.state[i][3] as usize];
        }
    }

    fn inv_sub_bytes(&mut self) {
        for i in 0..4 {
            self.state[i][0] = INV_S_BOX[self.state[i][0] as usize];
            self.state[i][1] = INV_S_BOX[self.state[i][1] as usize];
            self.state[i][2] = INV_S_BOX[self.state[i][2] as usize];
            self.state[i][3] = INV_S_BOX[self.state[i][3] as usize];
        }
    }

    fn shift_rows(&mut self) {
        for i in 0..4 {
            self.shift_row(i);
        }
    }

    fn shift_row(&mut self, row: usize) {
        let a = self.state[0][row];
        let b = self.state[1][row];
        let c = self.state[2][row];
        let d = self.state[3][row];

        if row == 1 {
            self.state[0][row] = b;
            self.state[1][row] = c;
            self.state[2][row] = d;
            self.state[3][row] = a;
        } else if row == 2 {
            self.state[0][row] = c;
            self.state[1][row] = d;
            self.state[2][row] = a;
            self.state[3][row] = b;
        } else if row == 3 {
            self.state[0][row] = d;
            self.state[1][row] = a;
            self.state[2][row] = b;
            self.state[3][row] = c;
        }
    }

    fn inv_shift_rows(&mut self) {
        for i in 0..4 {
            self.inv_shift_row(i);
        }
    }

    fn inv_shift_row(&mut self, row: usize) {
        let a = self.state[0][row];
        let b = self.state[1][row];
        let c = self.state[2][row];
        let d = self.state[3][row];

        if row == 1 {
            self.state[0][row] = d;
            self.state[1][row] = a;
            self.state[2][row] = b;
            self.state[3][row] = c;
        } else if row == 2 {
            self.state[0][row] = c;
            self.state[1][row] = d;
            self.state[2][row] = a;
            self.state[3][row] = b;
        } else if row == 3 {
            self.state[0][row] = b;
            self.state[1][row] = c;
            self.state[2][row] = d;
            self.state[3][row] = a;
        }
    }

    fn mix_columns(&mut self) {
        for i in 0..4 {
            Self::mix_column(&mut self.state[i]);
        }
    }

    fn mix_column(column: &mut [u8; 4]) {
        /*
        d0 = (2 * b0) ^ (3 * b1) ^ (1 * b2) ^ (1 * b3)
         */

        let a = column.clone();
        let mut b = [0u8; 4];

        for i in 0..4 {
            let h = (column[i] >> 7) & 1;
            b[i] = column[i] << 1;
            b[i] ^= h * 0x1b;
        }

        column[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
        column[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
        column[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
        column[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
    }

    fn inv_mix_columns(&mut self) {
        for i in 0..4 {
            Self::inv_mix_column(&mut self.state[i]);
        }
    }

    fn galois_multiplication(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0; /* accumulator for the product of the multiplication */

        while a != 0 && b != 0 {
            /* if the polynomial for b has a constant term, add the corresponding a to p */
            if b & 1 != 0 {
                p ^= a; /* addition in GF(2^m) is an XOR of the polynomial coefficients */
            }

            /* GF modulo: if a has a nonzero term x^7, then must be reduced when it becomes x^8 */
            let h = (a >> 7) & 1;
            a <<= 1;
            a ^= h * 0x1b;

            b >>= 1;
        }

        return p;
    }

    fn inv_mix_column(column: &mut [u8; 4]) {
        /*
        d0 = (2 * b0) ^ (3 * b1) ^ (1 * b2) ^ (1 * b3)
         */

        let a = column.clone();

        column[0] = Self::galois_multiplication(14, a[0])
            ^ Self::galois_multiplication(11, a[1])
            ^ Self::galois_multiplication(13, a[2])
            ^ Self::galois_multiplication(9, a[3]);
        column[1] = Self::galois_multiplication(9, a[0])
            ^ Self::galois_multiplication(14, a[1])
            ^ Self::galois_multiplication(11, a[2])
            ^ Self::galois_multiplication(13, a[3]);
        column[2] = Self::galois_multiplication(13, a[0])
            ^ Self::galois_multiplication(9, a[1])
            ^ Self::galois_multiplication(14, a[2])
            ^ Self::galois_multiplication(11, a[3]);
        column[3] = Self::galois_multiplication(11, a[0])
            ^ Self::galois_multiplication(13, a[1])
            ^ Self::galois_multiplication(9, a[2])
            ^ Self::galois_multiplication(14, a[3]);
    }
}

impl<'a> BlockCipher<'a> for AES {
    type Key = AESKey;
    type Block = [u8; 16];

    const BLOCK_SIZE: usize = 16;

    fn empty_block() -> Self::Block {
        return [0u8; Self::BLOCK_SIZE];
    }

    fn new(key: Self::Key, block: Self::Block) -> Self {
        let mut state = [[0u8; 4]; 4];

        for i in 0..4 as usize {
            state[i][0] = block[i * 4];
            state[i][1] = block[i * 4 + 1];
            state[i][2] = block[i * 4 + 2];
            state[i][3] = block[i * 4 + 3];
        }

        return Self { state, key };
    }

    fn encrypt(mut self) -> Self::Block {
        self.add_round_key(0);

        for i in 0..(self.key.variant().rounds_required() - 2) {
            self.encryption_round(i + 1);
        }

        self.sub_bytes();
        self.shift_rows();
        self.add_round_key(self.key.variant().rounds_required() - 1);

        return self.flattened_state();
    }

    fn decrypt(mut self) -> Self::Block {
        self.add_round_key(self.key.variant().rounds_required() - 1);
        self.inv_shift_rows();
        self.inv_sub_bytes();

        for i in (0..(self.key.variant().rounds_required() - 2)).rev() {
            self.decryption_round(i + 1);
        }

        self.add_round_key(0);

        return self.flattened_state();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_mix_column() {
        let mut input = [219, 19, 83, 69];

        AES::mix_column(&mut input);

        assert_eq!(input, [142, 77, 161, 188])
    }

    #[test]
    fn test_inv_mix_column() {
        let mut input = [142, 77, 161, 188];

        AES::inv_mix_column(&mut input);

        assert_eq!(input, [219, 19, 83, 69]);
    }

    mod aes_128 {
        use super::*;

        mod encrypt {
            use super::*;
            use pretty_assertions::assert_eq;

            #[test]
            fn test_initial_add_round_key_nist() {
                let key: [u32; 4] = [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c];
                let input: [u8; 16] = [
                    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0,
                    0x37, 0x07, 0x34,
                ];

                let mut cipher = AES::new(AESKey::new_aes128(key), input);

                cipher.add_round_key(0);

                assert_eq!(
                    cipher.state,
                    [
                        [0x19, 0x3d, 0xe3, 0xbe],
                        [0xa0, 0xf4, 0xe2, 0x2b],
                        [0x9a, 0xc6, 0x8d, 0x2a],
                        [0xe9, 0xf8, 0x48, 0x08]
                    ]
                );
            }

            #[test]
            fn test_initial_add_round_key_single_round_nist() {
                let key: [u32; 4] = [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c];
                let input: [u8; 16] = [
                    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0,
                    0x37, 0x07, 0x34,
                ];

                let mut cipher = AES::new(AESKey::new_aes128(key), input);

                cipher.add_round_key(0);
                cipher.encryption_round(1);

                assert_eq!(
                    cipher.state,
                    [
                        [0xa4, 0x9c, 0x7f, 0xf2],
                        [0x68, 0x9f, 0x35, 0x2b],
                        [0x6b, 0x5b, 0xea, 0x43],
                        [0x02, 0x6a, 0x50, 0x49]
                    ]
                );
            }

            #[test]
            fn test_aes_nist_vector_1() {
                let key: [u32; 4] = [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c];

                let input: [u8; 16] = [
                    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0,
                    0x37, 0x07, 0x34,
                ];

                let cipher = AES::new(AESKey::new_aes128(key), input);

                assert_eq!(
                    cipher.encrypt(),
                    [
                        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97,
                        0x19, 0x6a, 0x0b, 0x32
                    ]
                );
            }

            #[test]
            fn test_aes_nist_vector_2() {
                let key = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f];
                let input = [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ];

                assert_eq!(
                    AES::new(AESKey::new_aes128(key), input).encrypt(),
                    [
                        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80,
                        0x70, 0xb4, 0xc5, 0x5a
                    ]
                );
            }
        }

        mod decrypt {
            use super::*;
            use pretty_assertions::assert_eq;

            #[test]
            fn test_final_add_round_key_single_round_nist() {
                let key: [u32; 4] = [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c];
                let input: [u8; 16] = [
                    0xa4, 0x9c, 0x7f, 0xf2, 0x68, 0x9f, 0x35, 0x2b, 0x6b, 0x5b, 0xea, 0x43, 0x02,
                    0x6a, 0x50, 0x49,
                ];

                let mut cipher = AES::new(AESKey::new_aes128(key), input);

                cipher.decryption_round(1);
                cipher.add_round_key(0);

                assert_eq!(
                    cipher.state,
                    [
                        [0x32, 0x43, 0xf6, 0xa8],
                        [0x88, 0x5a, 0x30, 0x8d],
                        [0x31, 0x31, 0x98, 0xa2],
                        [0xe0, 0x37, 0x07, 0x34]
                    ]
                );
            }

            #[test]
            fn test_decrypt_nist_vector_1() {
                let key = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f];
                let input = [
                    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70,
                    0xb4, 0xc5, 0x5a,
                ];

                assert_eq!(
                    AES::new(AESKey::new_aes128(key), input,).decrypt(),
                    [
                        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                        0xcc, 0xdd, 0xee, 0xff,
                    ]
                );
            }
        }
    }

    mod aes_192 {
        use super::*;
        use pretty_assertions::assert_eq;

        #[test]
        fn test_encrypt_aes192_nist_vector_1() {
            let key: [u32; 6] = [
                0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617,
            ];

            let input: [u8; 16] = [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ];

            let cipher = AES::new(AESKey::new_aes192(key), input);

            assert_eq!(
                cipher.encrypt(),
                [
                    0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec,
                    0x0d, 0x71, 0x91
                ]
            );
        }

        #[test]
        fn test_decrypt_aes192_nist_vector_1() {
            let key: [u32; 6] = [
                0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617,
            ];

            let input: [u8; 16] = [
                0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d,
                0x71, 0x91,
            ];

            let cipher = AES::new(AESKey::new_aes192(key), input);

            assert_eq!(
                cipher.decrypt(),
                [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ]
            );
        }
    }

    mod aes_256 {
        use super::*;
        use pretty_assertions::assert_eq;

        #[test]
        fn test_encrypt_aes256_nist_vector_1() {
            let key: [u32; 8] = [
                0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b,
                0x1c1d1e1f,
            ];

            let input: [u8; 16] = [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ];

            let cipher = AES::new(AESKey::new_aes256(key), input);

            assert_eq!(
                cipher.encrypt(),
                [
                    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b,
                    0x49, 0x60, 0x89
                ]
            );
        }

        #[test]
        fn test_decrypt_aes256_nist_vector_1() {
            let key: [u32; 8] = [
                0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b,
                0x1c1d1e1f,
            ];

            let input: [u8; 16] = [
                0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
                0x60, 0x89,
            ];

            let cipher = AES::new(AESKey::new_aes256(key), input);

            assert_eq!(
                cipher.decrypt(),
                [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ]
            );
        }
    }
}
