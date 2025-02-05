use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;
use hex;

pub fn demo_clear_aes(number_of_outputs: usize, iv: &String, key: &String) -> Vec<Vec<u8>>{
    // Convert the key and IV from hexadecimal strings to byte arrays
    let key_bytes = hex::decode(key).expect("Invalid hex for key");
    let mut iv_bytes = hex::decode(iv).expect("Invalid hex for IV");

    // Ensure the key and IV are the correct lengths for AES-128
    assert_eq!(key_bytes.len(), 16, "Key must be 16 bytes for AES-128");
    assert_eq!(iv_bytes.len(), 16, "IV must be 16 bytes for AES-128");

    // Create a GenericArray for the key
    let key = GenericArray::from_slice(&key_bytes);

    // Initialize the AES-128 cipher
    let cipher = Aes128::new(&key);

    println!("Encrypted outputs:");

    let mut outputs = vec![];
    for _ in 0..number_of_outputs {
        // Treat the IV as a counter and increment it for each output
        let counter_block = iv_bytes.clone();

        // Create a mutable block for encryption
        let mut block = GenericArray::clone_from_slice(&counter_block);

        // Encrypt the block using AES-128 in ECB mode
        cipher.encrypt_block(&mut block);

        outputs.push(block.to_vec());

        // Increment the IV (counter) as a 128-bit value (big-endian)
        increment_iv_u8(&mut iv_bytes);
    }
    outputs
}


// Helper function to increment a 16-byte array (128-bit value) as a big-endian integer
pub fn increment_iv_u8(iv: &mut Vec<u8>) {
    for i in (0..16).rev() {
        if iv[i] == 0xFF {
            iv[i] = 0x00;
        } else {
            iv[i] += 1;
            break;
        }
    }
}


pub fn increment_iv_u64(iv: &mut Vec<u64>) {
    for i in (0..16).rev() {
        if iv[i] == 0xFF {
            iv[i] = 0x00;
        } else {
            iv[i] += 1;
            break;
        }
    }
}