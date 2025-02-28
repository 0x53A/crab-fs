// thanks, Claude!

use rand::{RngCore, SeedableRng, rngs::OsRng};
use rand_chacha::ChaCha20Rng;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};


pub fn entropy_from_keyboard() -> Vec<u8> {
    let mut entropy = Vec::new();
    println!("Please type random characters. Press Enter twice to finish.");
    println!("The timing between your keystrokes will be used as entropy.");
    
    let mut last_line = String::new();
    loop {
        print!("> ");
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        let start = SystemTime::now();
        io::stdin().read_line(&mut input).unwrap();
        
        // Break on empty line twice
        if input.trim().is_empty() && last_line.trim().is_empty() {
            break;
        }
        last_line = input.clone();
        
        // Collect entropy from:
        // 1. Timing of keystrokes (as nanos since epoch)
        let nanos = start
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_le_bytes();
        entropy.extend_from_slice(&nanos);
        
        // 2. The actual keys pressed
        entropy.extend_from_slice(input.as_bytes());
        
        // 3. Time taken to type the line
        let elapsed = start.elapsed().unwrap().as_nanos().to_le_bytes();
        entropy.extend_from_slice(&elapsed);
    }
    
    return entropy;
}


pub fn entropy_from_os() -> Vec<u8> {
    let mut bytes = vec![0u8; 32]; // 256 bits of entropy
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn rng_from_entropy(entropy: &[u8]) -> ChaCha20Rng {
    
    // Hash the entropy into a 32-byte seed using SHA-256
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(&entropy);
    let seed = hasher.finalize();
    
    // Create an RNG from the seed
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed);
    ChaCha20Rng::from_seed(seed_array)
}