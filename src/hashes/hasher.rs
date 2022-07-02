use core::cmp::min;
use core::default::Default;
use core::ops::{Index, IndexMut};

pub struct Hasher<H: HashingAlgorithm> {
    unprocessed_bytes: H::Chunk,
    algorithm: H,
    bytes_processed: u128,
    chunk_len: usize,
}

pub trait HashingAlgorithm
where
    Self: Sized + Default,
{
    type Chunk: IndexMut<usize> + AsMut<[u8]> + AsRef<[u8]>;
    type Output: Index<usize>;

    const CHUNK_SIZE: usize;
    const OUTPUT_SIZE: usize;
    const LENGTH_MODULO: u128;

    fn hasher() -> Hasher<Self> {
        return Hasher::new(Self::new());
    }

    fn hash(input: &[u8]) -> Self::Output {
        let mut hasher = Self::hasher();
        hasher.update(input);
        return hasher.finalize();
    }

    fn empty_chunk() -> Self::Chunk;

    fn new() -> Self {
        return Self::default();
    }

    /// This function should update the current state of the hash.
    /// * `chunk` - The chunk of data that has been provided, it will be of the exact value of `CHUNK_SIZE`.
    /// * 'bytes_processed' - The number of bytes that have been processed thus far. This includes the chunk being provided
    fn update(&mut self, chunk: &[u8], bytes_processed: u128);

    fn finalize(self, partial_chunk: &[u8], total_bytes_processed: u128) -> Self::Output;
}

impl<H: HashingAlgorithm> Hasher<H> {
    pub fn new(algorithm: H) -> Self {
        return Self {
            unprocessed_bytes: H::empty_chunk(),
            algorithm,
            bytes_processed: 0,
            chunk_len: 0,
        };
    }

    pub fn update(&mut self, input: &[u8]) {
        let mut total_processed = 0;

        while total_processed < input.len() {
            let amount_processed = self.fill_buffer(&input[total_processed..]);

            if self.buffer_is_full() {
                self.algorithm.update(
                    self.unprocessed_bytes.as_ref(),
                    self.bytes_processed + H::CHUNK_SIZE as u128,
                );

                self.chunk_len = 0;
            } else {
                self.chunk_len += amount_processed;
            }

            total_processed += amount_processed;
        }

        self.bytes_processed =
            self.bytes_processed.wrapping_add(input.len() as u128) % H::LENGTH_MODULO;
    }

    pub fn finalize(self) -> H::Output {
        return self.algorithm.finalize(
            &self.unprocessed_bytes.as_ref()[0..self.chunk_len],
            self.bytes_processed,
        );
    }

    fn fill_buffer(&mut self, input: &[u8]) -> usize {
        let amount_consumed = min(H::CHUNK_SIZE - self.chunk_len, input.len());

        self.unprocessed_bytes.as_mut()[self.chunk_len..self.chunk_len + amount_consumed]
            .copy_from_slice(&input[..amount_consumed]);

        return amount_consumed;
    }

    fn buffer_is_full(&self) -> bool {
        return self.chunk_len == H::CHUNK_SIZE;
    }
}
