use crate::block_ciphers::padding::Padding;
use crate::block_ciphers::BlockCipher;
use crate::error::VCryptoError;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

pub struct ECB<'a, C: BlockCipher<'a>> {
    key: C::Key,
    unprocessed_data: C::Block,
    unprocessed_data_len: usize,
    encrypted_data: Vec<u8>,
}

impl<'a, C: BlockCipher<'a>> ECB<'a, C> {
    pub fn new(key: C::Key) -> Self {
        return Self {
            key,
            unprocessed_data: C::empty_block(),
            unprocessed_data_len: 0,
            encrypted_data: Vec::new(),
        };
    }

    pub fn decrypt<P: Padding>(self, input: &[u8]) -> Result<Vec<u8>, VCryptoError> {
        if input.len() % C::BLOCK_SIZE != 0 {
            return Err(VCryptoError::InvalidInput);
        }

        let mut raw_decrypted_data = Vec::new();

        for i in 0..(input.len() / C::BLOCK_SIZE) {
            let mut c_block = C::empty_block();
            c_block
                .as_mut()
                .copy_from_slice(&input[i * C::BLOCK_SIZE..(i + 1) * C::BLOCK_SIZE]);

            raw_decrypted_data.extend_from_slice(C::new(self.key, c_block).decrypt().as_ref());
        }

        if let Some(padding_amount) = P::validate_padded_block(&raw_decrypted_data) {
            raw_decrypted_data.truncate(raw_decrypted_data.len().saturating_sub(padding_amount));

            return Ok(raw_decrypted_data);
        } else {
            return Err(VCryptoError::InvalidPadding)?;
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        if data.len() + self.unprocessed_data_len > C::BLOCK_SIZE {
            let remaining = data.len() + self.unprocessed_data_len;
            let mut amount_processed = 0;

            while (remaining - amount_processed) > C::BLOCK_SIZE {
                amount_processed += self.fill_buffer(&data[amount_processed..]);
                self.unprocessed_data_len = 0;

                let output_block = C::new(self.key, self.unprocessed_data).encrypt();
                self.encrypted_data.extend_from_slice(output_block.as_ref());
            }

            if (remaining - amount_processed) > 0 {
                self.unprocessed_data.as_mut()[0..(remaining - amount_processed)]
                    .copy_from_slice(&data[(data.len() - (remaining - amount_processed))..]);
                self.unprocessed_data_len = remaining - amount_processed;
            }
        } else {
            self.unprocessed_data.as_mut()
                [self.unprocessed_data_len..self.unprocessed_data_len + data.len()]
                .copy_from_slice(data);

            self.unprocessed_data_len += data.len();
        }
    }

    fn fill_buffer(&mut self, data: &[u8]) -> usize {
        self.unprocessed_data.as_mut()[self.unprocessed_data_len..]
            .copy_from_slice(&data[0..(C::BLOCK_SIZE - self.unprocessed_data_len)]);

        return C::BLOCK_SIZE - self.unprocessed_data_len;
    }

    pub fn finish<P: Padding>(mut self) -> Vec<u8> {
        let last_blocks = P::pad_block(
            &self.unprocessed_data.as_ref()[0..self.unprocessed_data_len],
            C::BLOCK_SIZE,
        );

        let mut temp = C::empty_block();

        temp.as_mut().copy_from_slice(&last_blocks.0);

        self.encrypted_data
            .extend_from_slice(C::new(self.key, temp).encrypt().as_ref());

        if let Some(l) = last_blocks.1 {
            temp.as_mut().copy_from_slice(&l);
            self.encrypted_data
                .extend_from_slice(C::new(self.key, temp).encrypt().as_ref());
        }

        return self.encrypted_data;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::block_ciphers::aes::{AESKey, AES};
    use crate::block_ciphers::padding::PKCS7;

    use pretty_assertions::assert_eq;

    #[test]
    fn test_encrypt_ecb_aes256_nist_vector_1() {
        let key: [u32; 8] = [
            0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b,
            0x1c1d1e1f,
        ];

        let input: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];

        let mut cipher = ECB::<AES>::new(AESKey::new_aes256(key));

        cipher.update(&input);

        assert_eq!(
            cipher.finish::<PKCS7>(),
            vec![
                0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
                0x60, 0x89, // Padding block
                0x9f, 0x3b, 0x75, 0x4, 0x92, 0x6f, 0x8b, 0xd3, 0x6e, 0x31, 0x18, 0xe9, 0x3, 0xa4,
                0xcd, 0x4a
            ]
        );
    }

    /*
     * Following test cases are sourced from https://chromium.googlesource.com/chromiumos/third_party/openssl/+/refs/heads/factory-2460.B/crypto/evp/evptests.txt
     */

    #[test]
    fn test_ecb_aes128_encrypt_decrypt() {
        let key: [u32; 8] = [
            0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b,
            0x1c1d1e1f,
        ];

        let pt = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();

        let mut encryptor = ECB::<AES>::new(AESKey::new_aes256(key));

        encryptor.update(&pt);
        let encrypted = encryptor.finish::<PKCS7>();

        let decryptor = ECB::<AES>::new(AESKey::new_aes256(key));

        assert_eq!(
            decryptor.decrypt::<PKCS7>(encrypted.as_slice()).unwrap(),
            pt
        );
    }
}
