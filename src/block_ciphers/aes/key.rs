use super::constants::{ROUND_CONSTANTS, S_BOX};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum AESVariant {
    AES128,
    AES192,
    AES256,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
enum AESKeyInner {
    AES128([u32; AESVariant::AES128.round_words()]),
    AES192([u32; AESVariant::AES192.round_words()]),
    AES256([u32; AESVariant::AES256.round_words()]),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct AESKey(AESKeyInner);

impl AESVariant {
    pub const fn bits(&self) -> usize {
        return match self {
            AESVariant::AES128 => 128,
            AESVariant::AES192 => 192,
            AESVariant::AES256 => 256,
        };
    }

    // The number of 32 bit words required
    pub(crate) const fn words_required(&self) -> usize {
        return self.bits() / 32;
    }

    pub const fn rounds_required(&self) -> u16 {
        return match self {
            AESVariant::AES128 => 11,
            AESVariant::AES192 => 13,
            AESVariant::AES256 => 15,
        };
    }

    pub(crate) const fn round_words(&self) -> usize {
        return 4 * self.rounds_required() as usize;
    }
}

impl AESKey {
    pub fn new_aes128(key: [u32; AESVariant::AES128.words_required()]) -> Self {
        return Self(AESKeyInner::AES128(Self::expand_key(key)));
    }

    pub fn new_aes192(key: [u32; AESVariant::AES192.words_required()]) -> Self {
        return Self(AESKeyInner::AES192(Self::expand_key(key)));
    }

    pub fn new_aes256(key: [u32; AESVariant::AES256.words_required()]) -> Self {
        return Self(AESKeyInner::AES256(Self::expand_key(key)));
    }

    pub fn variant(&self) -> AESVariant {
        return match self.0 {
            AESKeyInner::AES128(_) => AESVariant::AES128,
            AESKeyInner::AES192(_) => AESVariant::AES192,
            AESKeyInner::AES256(_) => AESVariant::AES256,
        };
    }

    pub(crate) fn get_round_key_word(&self, i: usize) -> u32 {
        return match self.0 {
            AESKeyInner::AES128(a) => a[i],
            AESKeyInner::AES192(a) => a[i],
            AESKeyInner::AES256(a) => a[i],
        };
    }

    fn expand_key<const N: usize, const W: usize>(key: [u32; N]) -> [u32; W] {
        let mut words = [0u32; W];

        for i in 0..W {
            if i < N {
                words[i] = key[i];
                continue;
            }

            let mut temp = words[i - 1];

            if i >= N && i % N == 0 {
                let a = Self::rot_word(words[i - 1]);
                let b = Self::sub_word(a);
                let c = ROUND_CONSTANTS[i / N - 1];
                temp = b ^ c;
            } else if i >= N && N > 6 && (i % N) == 4 {
                temp = Self::sub_word(words[i - 1]);
            }

            words[i] = words[i - N] ^ temp;
        }

        return words;
    }

    const fn sub_word(word: u32) -> u32 {
        return ((S_BOX[((word >> 24) & 0xff) as usize] as u32) << 24)
            | ((S_BOX[((word >> 16) & 0xff) as usize] as u32) << 16)
            | ((S_BOX[((word >> 8) & 0xff) as usize] as u32) << 8)
            | (S_BOX[(word & 0xff) as usize] as u32);
    }

    const fn rot_word(word: u32) -> u32 {
        return (word << 8 & 0xffffff00) | (word >> 24 & 0xff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_key_expansion_nist() {
        let key: [u32; 4] = [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c];
        let expected: [u32; 44] = [
            0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, 0xa0fafe17, 0x88542cb1, 0x23a33939,
            0x2a6c7605, 0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f, 0x3d80477d, 0x4716fe3e,
            0x1e237e44, 0x6d7a883b, 0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00, 0xd4d1c6f8,
            0x7c839d87, 0xcaf2b8bc, 0x11f915bc, 0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
            0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f, 0xead27321, 0xb58dbad2, 0x312bf560,
            0x7f8d292f, 0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, 0xd014f9a8, 0xc9ee2589,
            0xe13f0cc8, 0xb6630ca6,
        ];

        assert_eq!(AESKey::expand_key(key), expected);
    }

    #[test]
    fn test_key_expansion_other() {
        let key: [u32; 4] = [0x12fb34fa, 0x56f978f8, 0x9af7abf6, 0xbcf5cdf4];
        let expected: [u32; 44] = [
            0x12fb34fa, 0x56f978f8, 0x9af7abf6, 0xbcf5cdf4, 0xf5468b9f, 0xa3bff367, 0x39485891,
            0x85bd9565, 0x8d6cc608, 0x2ed3356f, 0x179b6dfe, 0x9226f89b, 0x7e2dd247, 0x50fee728,
            0x47658ad6, 0xd543724d, 0x6c6d3144, 0x3c93d66c, 0x7bf65cba, 0xaeb52ef7, 0xa95c59a0,
            0x95cf8fcc, 0xee39d376, 0x408cfd81, 0xed0855a9, 0x78c7da65, 0x96fe0913, 0xd672f492,
            0xedb71a5f, 0x9570c03a, 0x038ec929, 0xd5fc3dbb, 0xdd90f05c, 0x48e03066, 0x4b6ef94f,
            0x9e92c4f4, 0x898c4f57, 0xc16c7f31, 0x8a02867e, 0x1490428a, 0xdfa031ad, 0x1ecc4e9c,
            0x94cec8e2, 0x805e8a68,
        ];

        assert_eq!(AESKey::expand_key(key), expected);
    }

    #[test]
    fn test_rot_word() {
        assert_eq!(AESKey::rot_word(0xaabbccdd), 0xbbccddaa);
    }

    #[test]
    fn test_sub_word() {
        assert_eq!(AESKey::sub_word(0xaabbccdd), 0xacea4bc1);
    }
}
