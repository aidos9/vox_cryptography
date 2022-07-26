use super::constants::*;
use crate::error::VCryptoError;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BlowfishKey<'a> {
    key: &'a [u8],
}

impl<'a> BlowfishKey<'a> {
    pub fn new(key: &'a [u8]) -> Result<Self, VCryptoError> {
        if key.len() < BLOWFISH_KEY_MIN {
            return Err(VCryptoError::InvalidKeyLengthSmaller {
                key_length: key.len(),
                min: BLOWFISH_KEY_MIN,
            });
        } else if key.len() > BLOWFISH_KEY_MAX {
            return Err(VCryptoError::InvalidKeyLengthLarger {
                key_length: key.len(),
                max: BLOWFISH_KEY_MAX,
            });
        } else if key.len() % 4 != 0 {
            return Err(VCryptoError::InvalidKey);
        }

        return Ok(Self { key });
    }

    pub fn round_keys(self) -> [u32; 18] {
        let mut keys = BLOWFISH_P_ARRAY;

        for i in 0..keys.len() {
            let r = i * 4;

            keys[i] ^= u32::from_le(
                ((self.key[r % self.key.len()] as u32) << 24)
                    | ((self.key[(r + 1) % self.key.len()] as u32) << 16)
                    | ((self.key[(r + 2) % self.key.len()] as u32) << 8)
                    | (self.key[(r + 3) % self.key.len()] as u32),
            );
        }

        return keys;
    }
}
