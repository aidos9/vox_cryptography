use crate::hashes::{HashingAlgorithm, SHA1, SHA224, SHA256, SHA384, SHA512};
use crate::hmac::hmac;

pub fn pbkdf2<H: HashingAlgorithm, const O: usize>(
    password: &[u8],
    salt: &[u8],
    iterations: usize,
) -> [u8; O] {
    let mut working = [0u8; O];
    let mut amount_completed = 0;
    let mut iteration = 1;

    while (O - amount_completed) > H::OUTPUT_SIZE {
        working[amount_completed..amount_completed + H::OUTPUT_SIZE]
            .copy_from_slice(pbkdf2_f::<H>(password, salt, iteration, iterations).as_ref());

        amount_completed += H::OUTPUT_SIZE;
        iteration += 1;
    }

    if (O - amount_completed) > 0 {
        working[amount_completed..].copy_from_slice(
            &pbkdf2_f::<H>(password, salt, 1, iterations).as_ref()[0..(O - amount_completed)],
        );
    }

    return working;
}

fn pbkdf2_f<H: HashingAlgorithm>(password: &[u8], salt: &[u8], i: u32, c: usize) -> H::Output {
    let mut initial_salt = salt.to_vec();
    initial_salt.extend_from_slice(&i.to_be_bytes());

    let mut output = hmac::<H>(password, &initial_salt);
    let mut previous = output;

    for _ in 2..=c {
        // xor every byte with the new output
        previous = hmac::<H>(password, previous.as_ref());

        for (i, b) in previous.as_ref().into_iter().enumerate() {
            output.as_mut()[i] ^= *b;
        }
    }

    return output;
}

pub fn pbkdf2_hmac_sha1<const O: usize>(
    password: &[u8],
    salt: &[u8],
    iterations: usize,
) -> [u8; O] {
    return pbkdf2::<SHA1, O>(password, salt, iterations);
}

pub fn pbkdf2_hmac_sha224<const O: usize>(
    password: &[u8],
    salt: &[u8],
    iterations: usize,
) -> [u8; O] {
    return pbkdf2::<SHA224, O>(password, salt, iterations);
}

pub fn pbkdf2_hmac_sha256<const O: usize>(
    password: &[u8],
    salt: &[u8],
    iterations: usize,
) -> [u8; O] {
    return pbkdf2::<SHA256, O>(password, salt, iterations);
}

pub fn pbkdf2_hmac_sha384<const O: usize>(
    password: &[u8],
    salt: &[u8],
    iterations: usize,
) -> [u8; O] {
    return pbkdf2::<SHA384, O>(password, salt, iterations);
}

pub fn pbkdf2_hmac_sha512<const O: usize>(
    password: &[u8],
    salt: &[u8],
    iterations: usize,
) -> [u8; O] {
    return pbkdf2::<SHA512, O>(password, salt, iterations);
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_pbkdf2_sha1() {
        let password = b"my_password";
        let salt = hex::decode("b54bc5611be6de9720b8e9165de2c0f2").unwrap();
        let iterations = 4000;
        const OUTPUT_BYTES: usize = 160 / 8;

        assert_eq!(
            hex::encode(pbkdf2_hmac_sha1::<OUTPUT_BYTES>(
                password, &salt, iterations
            )),
            "85909a5b4fa1b904d2e7c48661498b9773ce2503"
        );
    }

    #[test]
    fn test_pbkdf2_sha1_2() {
        let password = b"plnlrtfpijpuhqylxbgqiiyipieyxvfsavzgxbbcfusqkozwpngsyejqlmjsytrmd";
        let salt = hex::decode("a009c1a485912c6ae630d3e744240b04").unwrap();
        let iterations = 1000;
        const OUTPUT_BYTES: usize = 128 / 8;

        assert_eq!(
            hex::encode(pbkdf2_hmac_sha1::<OUTPUT_BYTES>(
                password, &salt, iterations
            )),
            "17eb4014c8c461c300e9b61518b9a18b"
        );
    }

    #[test]
    fn test_pbkdf2_sha1_long_inputs() {
        let password = b"this test should be longer than one block and a bit longer than 2 blocks. This means it must be 3 or more blocks, how about that! Well this last bit of text is just filling for space :)";
        let salt = hex::decode("a009c1a485912c6ae630d3e744240b04a009c1a485912c6ae630d3e744240b04a009c1a485912c6ae630d3e744240b04a009c1a485912c6ae630d3e744240b04a009c1a485912c6ae630d3e744240b04a009c1a485912c6ae630d3e744240b04").unwrap();
        let iterations = 20000;
        const OUTPUT_BYTES: usize = 160 / 8;

        assert_eq!(
            hex::encode(pbkdf2_hmac_sha1::<OUTPUT_BYTES>(
                password, &salt, iterations
            )),
            "57514ed7177a1825d4629c12132623b2ba456aa6"
        );
    }
}
