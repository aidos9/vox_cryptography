use super::constants::*;
use super::BlowfishKey;
use crate::block_ciphers::BlockCipher;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Blowfish {
    round_keys: [u32; 18],
    s_boxes: [[u32; 256]; 4],
    block_left: u32,
    block_right: u32,
}

impl Blowfish {
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

impl<'a> BlockCipher<'a> for Blowfish {
    type Key = BlowfishKey<'a>;

    type Block = [u8; 8];

    const BLOCK_SIZE: usize = 8;

    fn empty_block() -> Self::Block {
        return [0u8; Self::BLOCK_SIZE];
    }

    fn new(key: Self::Key, block: Self::Block) -> Self {
        let block_left = u32::from_le(
            ((block[0] as u32) << 24)
                | ((block[1] as u32) << 16)
                | ((block[2] as u32) << 8)
                | (block[3] as u32),
        );

        let block_right = u32::from_le(
            ((block[4] as u32) << 24)
                | ((block[5] as u32) << 16)
                | ((block[6] as u32) << 8)
                | (block[7] as u32),
        );

        let mut s = Self {
            round_keys: key.round_keys(),
            s_boxes: BLOWFISH_S_BOXES,
            block_left,
            block_right,
        };

        s.expand_key();

        return s;
    }

    fn encrypt(mut self) -> Self::Block {
        (self.block_left, self.block_right) =
            self.blowfish_encrypt(self.block_left, self.block_right);

        let mut output = [0u8; 8];

        output[0..4].copy_from_slice(&self.block_left.to_be_bytes());
        output[4..8].copy_from_slice(&self.block_right.to_be_bytes());

        return output;
    }

    fn decrypt(mut self) -> Self::Block {
        (self.block_left, self.block_right) =
            self.blowfish_decrypt(self.block_left, self.block_right);

        let mut output = [0u8; 8];

        output[0..4].copy_from_slice(&self.block_left.to_be_bytes());
        output[4..8].copy_from_slice(&self.block_right.to_be_bytes());

        return output;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_blowfish_test_1() {
        let key = hex::decode("0000000000000000").unwrap();
        let mut pt = [0u8; 8];
        hex::decode_to_slice("0000000000000000", &mut pt).unwrap();

        let encryptor = Blowfish::new(BlowfishKey::new(&key).unwrap(), pt.into());

        assert_eq!(hex::encode(encryptor.encrypt()), "4ef997456198dd78");
    }

    #[test]
    fn test_blowfish_test_2() {
        let key = hex::decode("ffffffffffffffff").unwrap();
        let mut pt = [0u8; 8];
        hex::decode_to_slice("ffffffffffffffff", &mut pt).unwrap();

        let encryptor = Blowfish::new(BlowfishKey::new(&key).unwrap(), pt);

        assert_eq!(hex::encode(encryptor.encrypt()), "51866fd5b85ecb8a");
    }
}
