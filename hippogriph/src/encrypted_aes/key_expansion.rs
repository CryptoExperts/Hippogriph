use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use tfhe::odd::prelude::*;

use crate::encrypted_aes::{clear::clear_sub_bytes, decomposer, recomposer, AESStateBoolean};




fn rot_words_key_expansion(bits : &mut Vec<Ciphertext>){
    assert_eq!(bits.len(), 32);
    bits.rotate_left(8);
}


 fn send_bits_to_nibbles_key_expansion(bits : &Vec<Ciphertext>, server_key : &ServerKey) -> Vec<Ciphertext>{
    assert_eq!(bits.len(), 32);
    let encoding_arithmetic = Encoding::new_canonical(16, (0..16).collect(), 17);

    (0..8)
        .into_par_iter() 
        .map(|i| bits[i*4..(i+1)*4].to_vec())
        .map(|v| recomposer(&v, &encoding_arithmetic, &server_key))
        .collect()
}


 fn sub_words_key_expansion(nibbles : Vec<Ciphertext>, server_key : &ServerKey) -> Vec<Ciphertext>{
    assert_eq!(nibbles.len(), 8);
    (0..4)
            .into_par_iter()  
            .map(|i| nibbles[i*2..(i+1)*2].to_vec())
            .map(|v| server_key.full_tree_bootstrapping(&v, 
                                                                    &vec![Encoding::new_canonical(16, (0..16).collect(), 17);2],
                                                                    256,
                                                                    &clear_sub_bytes))
            .collect::<Vec<Vec<Ciphertext>>>()
            .concat()
}

fn send_nibbles_to_bits_key_expansion(nibbles : &Vec<Ciphertext>,  server_key : &ServerKey) -> Vec<Ciphertext>{
    assert_eq!(nibbles.len(), 8);
    nibbles
        .par_iter() 
        .map(|x| decomposer(x, &Encoding::parity_encoding(), server_key))
        .collect::<Vec<Vec<Ciphertext>>>()
        .concat()
}



fn add_round_constant_key_expansion(bits: &mut Vec<Ciphertext>, rcon_int : u8, server_key : &ServerKey){
    assert_eq!(bits.len(), 32);
    let rcon: Vec<bool> = (0..8).map(|i| (rcon_int >> (7 - i)) % 2 == 1).collect();
    // only affects the first byte of the last row, 
    for j in 0..8{
        if rcon[j]{
            bits[j] = server_key.simple_plaintext_sum(&bits[j], 1, 2);
        }
    }
}



impl AESStateBoolean{
    pub fn next_round_keys(&mut self, twisted_row : Vec<Ciphertext>, server_key : &ServerKey){
        let mut buffer = twisted_row;
        for i in 0..4{
            let new_row : Vec<Ciphertext> = (0..32)
                                            .map(|j_bit| server_key.simple_sum(&vec![self.bits[i * 32 + j_bit].clone(), buffer[j_bit].clone()]))
                                            .collect();
            new_row.iter().enumerate().for_each(|(j_bit, c)| self.bits[i * 32 + j_bit] = c.clone());
            buffer = new_row;
        }
    }

    pub fn extract_last_row(&self) -> Vec<Ciphertext>{
        self.bits[32 * 3..].to_vec()
    }
}



pub fn encrypted_key_expansion(encrypted_key: Vec<Ciphertext>, server_key :  &ServerKey) -> Vec<Vec<Ciphertext>>{
    // We use the same structures that for the encryption
    assert_eq!(encrypted_key.len(), 128);

    static ROUND_CONSTANTS: [u8;11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];


    let state_boolean = AESStateBoolean{bits: encrypted_key};
    let mut state_round_keys: Vec<AESStateBoolean> = Vec::with_capacity(11);
    
    // The key of the first round remains unchanged
    state_round_keys.push(state_boolean);

    for i in 1..11{
        // Extract and clone the last row
        let mut bits_last_row = state_round_keys[i - 1].extract_last_row();

        // apply the rotation
        rot_words_key_expansion(&mut bits_last_row);

        // send the bits to nibbles
        let mut nibbles_last_row = send_bits_to_nibbles_key_expansion(&bits_last_row, &server_key);


        // apply the subword to every word, but first we need to recompose them in nibbles
        nibbles_last_row = sub_words_key_expansion(nibbles_last_row, &server_key);

        
        // resend everyone into the boolean world
        bits_last_row = send_nibbles_to_bits_key_expansion(&nibbles_last_row, &server_key);

        
        // add the round counstant
        add_round_constant_key_expansion(&mut bits_last_row, ROUND_CONSTANTS[i], &server_key);
        
        // compute the union of both state
        let mut current_round_key =  state_round_keys[i-1].clone();
        current_round_key.next_round_keys(bits_last_row, &server_key);
        state_round_keys.push(current_round_key);
    }
    
    state_round_keys.into_iter().map(|state| state.bits).collect()
}