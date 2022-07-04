use criterion::{criterion_group, criterion_main, Criterion};
use vox_cryptography::block_ciphers::aes::{AESKey, AES};
use vox_cryptography::block_ciphers::blowfish::{Blowfish, BlowfishKey};

fn aes_128_benchmark(c: &mut Criterion) {
    c.bench_function("aes128 - encrypt nist vector 1", |b| {
        b.iter(|| {
            AES::new(
                AESKey::new_aes128([0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c]),
                [
                    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0,
                    0x37, 0x07, 0x34,
                ],
            )
            .encrypt()
        })
    });

    c.bench_function("aes128 - decrypt nist vector 1", |b| {
        b.iter(|| {
            AES::new(
                AESKey::new_aes128([0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c]),
                [
                    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70,
                    0xb4, 0xc5, 0x5a,
                ],
            )
            .decrypt()
        })
    });
}

fn aes_256_benchmark(c: &mut Criterion) {
    c.bench_function("aes256 - encrypt nist vector 1", |b| {
        b.iter(|| {
            AES::new(
                AESKey::new_aes256([
                    0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617,
                    0x18191a1b, 0x1c1d1e1f,
                ]),
                [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ],
            )
            .encrypt()
        })
    });

    c.bench_function("aes256 - decrypt nist vector 1", |b| {
        b.iter(|| {
            AES::new(
                AESKey::new_aes256([
                    0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617,
                    0x18191a1b, 0x1c1d1e1f,
                ]),
                [
                    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b,
                    0x49, 0x60, 0x89,
                ],
            )
            .decrypt()
        })
    });
}

fn blowfish_benchmark(c: &mut Criterion) {
    c.bench_function("blowfish - single block encryption", |b| {
        b.iter(|| {
            Blowfish::new(
                BlowfishKey::new(&[0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e]).unwrap(),
                [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            )
            .encrypt()
        })
    });

    c.bench_function("blowfish - single block decryption", |b| {
        b.iter(|| {
            Blowfish::new(
                BlowfishKey::new(&[0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e]).unwrap(),
                [0xa7, 0x90, 0x79, 0x51, 0x08, 0xea, 0x3c, 0xae],
            )
            .decrypt()
        })
    });
}

criterion_group!(
    hashes,
    aes_128_benchmark,
    aes_256_benchmark,
    blowfish_benchmark
);

criterion_main!(hashes);
