// Thanks, Claude!

use num_traits::{PrimInt, WrappingAdd};
use std::ops::BitXor;

/// A generic implementation of a Feistel network that works with different integer types
pub struct FeistelNetwork<T, U>
where
    T: PrimInt + WrappingAdd, // Full block type
    U: PrimInt + WrappingAdd, // Half block type
{
    num_rounds: usize,
    keys: Vec<U>,
    _phantom: std::marker::PhantomData<T>,
}

pub trait FeistelBlock: PrimInt + WrappingAdd {
    type HalfBlock: PrimInt + WrappingAdd;

    fn split(self) -> (Self::HalfBlock, Self::HalfBlock);
    fn join(left: Self::HalfBlock, right: Self::HalfBlock) -> Self;
    fn block_size() -> usize;
}

// Implementation for u64/u32 pair
impl FeistelBlock for u64 {
    type HalfBlock = u32;

    fn split(self) -> (Self::HalfBlock, Self::HalfBlock) {
        ((self >> 32) as u32, self as u32)
    }

    fn join(left: Self::HalfBlock, right: Self::HalfBlock) -> Self {
        ((left as u64) << 32) | (right as u64)
    }

    fn block_size() -> usize {
        64
    }
}

// Implementation for u32/u16 pair
impl FeistelBlock for u32 {
    type HalfBlock = u16;

    fn split(self) -> (Self::HalfBlock, Self::HalfBlock) {
        ((self >> 16) as u16, self as u16)
    }

    fn join(left: Self::HalfBlock, right: Self::HalfBlock) -> Self {
        ((left as u32) << 16) | (right as u32)
    }

    fn block_size() -> usize {
        32
    }
}

// Implementation for u16/u8 pair
impl FeistelBlock for u16 {
    type HalfBlock = u8;

    fn split(self) -> (Self::HalfBlock, Self::HalfBlock) {
        ((self >> 8) as u8, self as u8)
    }

    fn join(left: Self::HalfBlock, right: Self::HalfBlock) -> Self {
        ((left as u16) << 8) | (right as u16)
    }

    fn block_size() -> usize {
        16
    }
}

impl<T, U> FeistelNetwork<T, U>
where
    T: FeistelBlock<HalfBlock = U>,
    U: PrimInt + WrappingAdd + BitXor<Output = U> + Copy,
{
    /// Create a new Feistel network with the specified number of rounds and keys
    pub fn new(num_rounds: usize, keys: Vec<U>) -> Self {
        if keys.len() != num_rounds {
            panic!("Number of keys must match number of rounds");
        }

        FeistelNetwork {
            num_rounds,
            keys,
            _phantom: std::marker::PhantomData,
        }
    }

    /// The round function - in practice, this should be more complex
    fn round_function(&self, input: U, key: U) -> U {
        // Simple round function using wrapping addition and XOR
        input.wrapping_add(&key).rotate_left(3)
    }

    /// Encrypt a block using the Feistel network
    pub fn encrypt(&self, plaintext: T) -> T {
        let (mut left, mut right) = plaintext.split();

        // Apply the Feistel rounds
        for i in 0..self.num_rounds {
            let temp = right;
            right = left ^ self.round_function(right, self.keys[i]);
            left = temp;
        }

        T::join(right, left)
    }

    /// Decrypt a block using the Feistel network
    pub fn decrypt(&self, ciphertext: T) -> T {
        let (mut left, mut right) = ciphertext.split();

        // Apply the Feistel rounds in reverse
        for i in (0..self.num_rounds).rev() {
            let temp = right;
            right = left ^ self.round_function(right, self.keys[i]);
            left = temp;
        }

        T::join(right, left)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u64_encryption_decryption() {
        let keys = vec![0x1234u32, 0x5678, 0x9ABC, 0xDEF0];
        let network = FeistelNetwork::<u64, u32>::new(4, keys);

        let plaintext = 0x123456789ABCDEF0u64;
        let ciphertext = network.encrypt(plaintext);
        let decrypted = network.decrypt(ciphertext);

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_u32_encryption_decryption() {
        let keys = vec![0x1234u16, 0x5678, 0x9ABC, 0xDEF0];
        let network = FeistelNetwork::<u32, u16>::new(4, keys);

        let plaintext = 0x12345678u32;
        let ciphertext = network.encrypt(plaintext);
        let decrypted = network.decrypt(ciphertext);

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_u16_encryption_decryption() {
        let keys = vec![0x12u8, 0x34, 0x56, 0x78];
        let network = FeistelNetwork::<u16, u8>::new(4, keys);

        let plaintext = 0x1234u16;
        let ciphertext = network.encrypt(plaintext);
        let decrypted = network.decrypt(ciphertext);

        assert_eq!(plaintext, decrypted);
    }
}
