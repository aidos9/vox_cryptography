use core::ops::IndexMut;

pub trait BlockCipher<'a> {
    type Key: Clone + Copy;
    type Block: IndexMut<usize> + AsMut<[u8]> + AsRef<[u8]> + Clone + Copy;

    const BLOCK_SIZE: usize;

    fn empty_block() -> Self::Block;

    fn new(key: Self::Key, block: Self::Block) -> Self;

    fn encrypt(self) -> Self::Block;

    fn decrypt(self) -> Self::Block;
}
