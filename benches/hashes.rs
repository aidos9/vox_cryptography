use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vox_cryptography::hashes::{BLAKE2b, HashingAlgorithm, MD5, SHA1, SHA256, SHA512};

fn sha256_benchmark(c: &mut Criterion) {
    c.bench_function("sha256 - empty", |b| {
        b.iter(|| SHA256::hash(black_box(&[])))
    });

    c.bench_function(
        "sha256 - 'The quick brown fox jumped over the lazy dog.'",
        |b| b.iter(|| SHA256::hash(black_box(b"The quick brown fox jumped over the lazy dog."))),
    );

    let input_str = std::iter::repeat("The quick brown fox jumped over the lazy dog.\n")
        .take(100_000)
        .collect::<String>();
    let input = input_str.as_bytes();

    c.bench_function(
        "sha256 - 'The quick brown fox jumped over the lazy dog.' * 100,000",
        |b| b.iter(|| SHA256::hash(black_box(input))),
    );
}

fn sha512_benchmark(c: &mut Criterion) {
    c.bench_function("sha512 - empty", |b| {
        b.iter(|| SHA512::hash(black_box(&[])))
    });

    c.bench_function(
        "sha512 - 'The quick brown fox jumped over the lazy dog.'",
        |b| b.iter(|| SHA512::hash(black_box(b"The quick brown fox jumped over the lazy dog."))),
    );

    let input_str = std::iter::repeat("The quick brown fox jumped over the lazy dog.\n")
        .take(100_000)
        .collect::<String>();
    let input = input_str.as_bytes();

    c.bench_function(
        "sha512 - 'The quick brown fox jumped over the lazy dog.' * 100,000",
        |b| b.iter(|| SHA512::hash(black_box(input))),
    );
}

fn md5_benchmark(c: &mut Criterion) {
    c.bench_function("md5 - empty", |b| b.iter(|| MD5::hash(black_box(&[]))));

    c.bench_function(
        "md5 - 'The quick brown fox jumped over the lazy dog.'",
        |b| b.iter(|| MD5::hash(black_box(b"The quick brown fox jumped over the lazy dog."))),
    );

    let input_str = std::iter::repeat("The quick brown fox jumped over the lazy dog.\n")
        .take(100_000)
        .collect::<String>();
    let input = input_str.as_bytes();

    c.bench_function(
        "md5 - 'The quick brown fox jumped over the lazy dog.' * 100,000",
        |b| b.iter(|| MD5::hash(black_box(input))),
    );
}

fn sha1_benchmark(c: &mut Criterion) {
    c.bench_function("sha1 - empty", |b| b.iter(|| SHA1::hash(black_box(&[]))));

    c.bench_function(
        "sha1 - 'The quick brown fox jumped over the lazy dog.'",
        |b| b.iter(|| SHA1::hash(black_box(b"The quick brown fox jumped over the lazy dog."))),
    );

    let input_str = std::iter::repeat("The quick brown fox jumped over the lazy dog.\n")
        .take(100_000)
        .collect::<String>();
    let input = input_str.as_bytes();

    c.bench_function(
        "sha1 - 'The quick brown fox jumped over the lazy dog.' * 100,000",
        |b| b.iter(|| SHA1::hash(black_box(input))),
    );
}

fn blake2b_benchmark(c: &mut Criterion) {
    c.bench_function("blake2b - empty", |b| {
        b.iter(|| BLAKE2b::hash(black_box(&[])))
    });

    c.bench_function(
        "blake2b - 'The quick brown fox jumped over the lazy dog.'",
        |b| b.iter(|| BLAKE2b::hash(black_box(b"The quick brown fox jumped over the lazy dog."))),
    );

    let input_str = std::iter::repeat("The quick brown fox jumped over the lazy dog.\n")
        .take(100_000)
        .collect::<String>();
    let input = input_str.as_bytes();

    c.bench_function(
        "blake2b - 'The quick brown fox jumped over the lazy dog.' * 100,000",
        |b| b.iter(|| BLAKE2b::hash(black_box(input))),
    );
}

criterion_group!(
    hashes,
    sha256_benchmark,
    sha512_benchmark,
    sha1_benchmark,
    md5_benchmark,
    blake2b_benchmark
);

criterion_main!(hashes);
