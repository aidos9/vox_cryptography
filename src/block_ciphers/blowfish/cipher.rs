use super::constants::*;
use super::BlowfishKey;
use crate::error::VCryptoError;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Blowfish {
    round_keys: [u32; 18],
    s_boxes: [[u32; 256]; 4],
    block_left: u32,
    block_right: u32,
}

impl Blowfish {
    pub fn new(key: BlowfishKey) -> Self {
        let mut s = Self {
            round_keys: key.round_keys(),
            s_boxes: BLOWFISH_S_BOXES,
            block_left: 0,
            block_right: 0,
        };

        s.expand_key();

        return s;
    }

    fn expand_key(&mut self) {
        let mut l = 0x0;
        let mut r = 0x0;

        for i in (0..18).step_by(2) {
            (l, r) = self.blowfish_encrypt(l, r);
            self.round_keys[i] = l;
            self.round_keys[i + 1] = r;
        }

        for i in 0..4 {
            for c in (0..256).step_by(2) {
                (l, r) = self.blowfish_encrypt(l, r);
                self.s_boxes[i][c] = l;
                self.s_boxes[i][c + 1] = r;
            }
        }
    }

    pub fn encrypt(mut self, block: &[u8]) -> Result<[u8; 8], VCryptoError> {
        if block.len() != 8 {
            return Err(VCryptoError::InvalidBlockSize {
                block_size: block.len(),
                expected: 8,
            });
        }

        self.block_left = u32::from_le(
            ((block[0] as u32) << 24)
                | ((block[1] as u32) << 16)
                | ((block[2] as u32) << 8)
                | (block[3] as u32),
        );

        self.block_right = u32::from_le(
            ((block[4] as u32) << 24)
                | ((block[5] as u32) << 16)
                | ((block[6] as u32) << 8)
                | (block[7] as u32),
        );

        (self.block_left, self.block_right) =
            self.blowfish_encrypt(self.block_left, self.block_right);

        let mut output = [0u8; 8];

        output[0..4].copy_from_slice(&self.block_left.to_be_bytes());
        output[4..8].copy_from_slice(&self.block_right.to_be_bytes());

        return Ok(output);
    }

    pub fn decrypt(mut self, block: &[u8]) -> Result<[u8; 8], VCryptoError> {
        if block.len() != 8 {
            return Err(VCryptoError::InvalidBlockSize {
                block_size: block.len(),
                expected: 8,
            });
        }

        self.block_left = u32::from_le(
            ((block[0] as u32) << 24)
                | ((block[1] as u32) << 16)
                | ((block[2] as u32) << 8)
                | (block[3] as u32),
        );

        self.block_right = u32::from_le(
            ((block[4] as u32) << 24)
                | ((block[5] as u32) << 16)
                | ((block[6] as u32) << 8)
                | (block[7] as u32),
        );

        (self.block_left, self.block_right) =
            self.blowfish_decrypt(self.block_left, self.block_right);

        let mut output = [0u8; 8];

        output[0..4].copy_from_slice(&self.block_left.to_be_bytes());
        output[4..8].copy_from_slice(&self.block_right.to_be_bytes());

        return Ok(output);
    }

    fn blowfish_encrypt(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        for i in 0..16 {
            (l, r) = self.blowfish_round(i, l, r);
        }

        (l, r) = (r, l);

        r ^= self.round_keys[16];
        l ^= self.round_keys[17];

        return (l, r);
    }

    fn blowfish_decrypt(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        for i in 0..16 {
            (l, r) = self.blowfish_round(17 - i, l, r);
        }

        (l, r) = (r, l);

        r ^= self.round_keys[1];
        l ^= self.round_keys[0];

        return (l, r);
    }

    fn blowfish_round(&self, round: usize, mut l: u32, mut r: u32) -> (u32, u32) {
        l ^= self.round_keys[round];
        let l_bytes = l.to_be_bytes();

        let f = self.round_f_function(l_bytes[0], l_bytes[1], l_bytes[2], l_bytes[3]);
        r ^= f;

        return (r, l);
    }

    fn round_f_function(&self, a: u8, b: u8, c: u8, d: u8) -> u32 {
        return (self.s_boxes[0][a as usize].wrapping_add(self.s_boxes[1][b as usize])
            ^ self.s_boxes[2][c as usize])
            .wrapping_add(self.s_boxes[3][d as usize]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_blowfish_test_1() {
        let key = hex::decode("0000000000000000").unwrap();
        let pt = hex::decode("0000000000000000").unwrap();

        let encryptor = Blowfish::new(BlowfishKey::new(&key).unwrap());

        assert_eq!(
            hex::encode(encryptor.encrypt(&pt).unwrap()),
            "4ef997456198dd78"
        );
    }

    #[test]
    fn test_blowfish_test_2() {
        let key = hex::decode("ffffffffffffffff").unwrap();
        let pt = hex::decode("ffffffffffffffff").unwrap();

        let encryptor = Blowfish::new(BlowfishKey::new(&key).unwrap());

        assert_eq!(
            hex::encode(encryptor.encrypt(&pt).unwrap()),
            "51866fd5b85ecb8a"
        );
    }
}
