use crate::hashes::{HashingAlgorithm, MD5, SHA1, SHA224, SHA256, SHA384, SHA512};

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

const OPAD: u8 = 0x5c;
const IPAD: u8 = 0x36;

pub(crate) fn hmac<H: HashingAlgorithm>(key: &[u8], msg: &[u8]) -> H::Output {
    let mut o_kp = H::empty_chunk();
    let mut dbl: Vec<u8> = Vec::with_capacity(H::CHUNK_SIZE * 2);
    let mut i_kp: Vec<u8> = Vec::with_capacity(H::CHUNK_SIZE + msg.len());

    if key.len() > H::CHUNK_SIZE {
        o_kp.as_mut()[0..H::OUTPUT_SIZE].copy_from_slice(H::hash(key).as_ref())
    } else {
        o_kp.as_mut()[0..key.len()].copy_from_slice(key);
    }

    for i in 0..o_kp.as_ref().len() {
        i_kp.push(o_kp.as_ref()[i] ^ IPAD);
    }

    i_kp.extend_from_slice(msg);

    for i in 0..o_kp.as_ref().len() {
        dbl.push(o_kp.as_ref()[i] ^ OPAD);
    }

    dbl.extend_from_slice(H::hash(&i_kp).as_ref());

    return H::hash(&dbl);
}

pub fn hmac_sha224(key: &[u8], msg: &[u8]) -> <SHA224 as HashingAlgorithm>::Output {
    return hmac::<SHA224>(key, msg);
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> <SHA256 as HashingAlgorithm>::Output {
    return hmac::<SHA256>(key, msg);
}

pub fn hmac_sha384(key: &[u8], msg: &[u8]) -> <SHA384 as HashingAlgorithm>::Output {
    return hmac::<SHA384>(key, msg);
}

pub fn hmac_sha512(key: &[u8], msg: &[u8]) -> <SHA512 as HashingAlgorithm>::Output {
    return hmac::<SHA512>(key, msg);
}

pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> <SHA1 as HashingAlgorithm>::Output {
    return hmac::<SHA1>(key, msg);
}

pub fn hmac_md5(key: &[u8], msg: &[u8]) -> <MD5 as HashingAlgorithm>::Output {
    return hmac::<MD5>(key, msg);
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::encode;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_hmac_md5() {
        let key = b"key";
        let input = b"The quick brown fox jumps over the lazy dog";

        assert_eq!(
            encode(hmac_md5(key, input)),
            "80070713463e7749b90c2dc24911e275"
        );
    }

    #[test]
    fn test_hmac_sha1() {
        let key = b"key";
        let input = b"The quick brown fox jumps over the lazy dog";

        assert_eq!(
            encode(hmac_sha1(key, input)),
            "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
        );
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"key";
        let input = b"The quick brown fox jumps over the lazy dog";

        assert_eq!(
            encode(hmac_sha256(key, input)),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn test_hmac_sha256_large_key() {
        let key = b"The quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dog";
        let input = b"message";

        assert_eq!(
            encode(hmac_sha256(key, input)),
            "5597b93a2843078cbb0c920ae41dfe20f1685e10c67e423c11ab91adfc319d12"
        );
    }
}
