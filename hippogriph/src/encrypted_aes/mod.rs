use std::time::Instant;

use crate::clear_aes::increment_iv_u64;

use clear::clear_sub_bytes;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use tfhe::{core_crypto::prelude::DynamicDistribution, odd::prelude::*};

// use crate::encrypted_aes::aes_utils::{pretty_print_clear, u8_to_vec_bool_integer};

use self::{casts::{decomposer, recomposer}, linear_circuit::LinearCircuit};

mod linear_circuit;
mod casts;
mod clear;


#[derive(Clone)]
pub struct AESStateBoolean{
    pub bits : Vec<Ciphertext>
}


impl AESStateBoolean{
    pub fn tfhe_encryption_bits(m : &Vec<u64>, client_key : &ClientKey) -> Self{
        assert_eq!(m.len(), 128);

        let parity_encoding = Encoding::parity_encoding();
        Self { bits:  
            m.iter().map(|b| client_key.encrypt_arithmetic(*b, &parity_encoding)).collect()
        }
    }


    pub fn tfhe_decryption_bits(&self, client_key : &ClientKey) -> Vec<u64>{
        self.bits.iter().map(|c| client_key.decrypt(c)).collect()       
    }


    
    //getter
    pub fn square_getter(&self, row : usize, col : usize, bit : usize) -> &Ciphertext{
        &self.bits[col * 8 * 4 + row * 8 + bit]
    }

    pub fn aes_recomposer(&self, server_key : &ServerKey)-> AESStateArithmetic{
        let encoding_arithmetic = Encoding::new_canonical(16, (0..16).collect(), 17);
        AESStateArithmetic{
            nibbles : (0..32)
                    .into_par_iter() //comment this line to deactivate parallelization
                    .map(|i| self.bits[i*4..(i+1)*4].to_vec())
                    .map(|v| recomposer(&v, &encoding_arithmetic, &server_key))
                    .collect(),
            encoding : encoding_arithmetic
        }
    }



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



pub struct AESStateArithmetic{
    pub nibbles : Vec<Ciphertext>, //each nibble is 4-bits long
    pub encoding : Encoding
}



impl AESStateArithmetic{

    pub fn aes_decomposer(&self, server_key : &ServerKey) -> AESStateBoolean{
        AESStateBoolean{
            bits : self.nibbles
            .par_iter()
            .map(|x| decomposer(x, &Encoding::parity_encoding(), server_key))
            .collect::<Vec<Vec<Ciphertext>>>()
            .concat()
        }
     }

}



fn sub_bytes(state : &AESStateArithmetic, server_key:&ServerKey) -> AESStateArithmetic{
    assert_eq!(state.nibbles.len(), 32);
    AESStateArithmetic{
        nibbles : (0..16)
                .into_par_iter()
                .map(|i| state.nibbles[i*2..(i+1)*2].to_vec())
                .map(|v| server_key.full_tree_bootstrapping(&v, 
                                                                        &vec![state.encoding.clone();2],
                                                                        256,
                                                                        &clear_sub_bytes
                                                                    ))
                .collect::<Vec<Vec<Ciphertext>>>()
                .concat(),
        encoding : state.encoding.clone()
    }
}




fn add_round_key(state : &AESStateBoolean, round_key : &Vec<Ciphertext>, server_key:&ServerKey) -> AESStateBoolean{
    assert_eq!(state.bits.len(), 128);
    assert_eq!(round_key.len(), 128);
    AESStateBoolean { bits: state.bits.iter()
                                .zip(round_key)
                                .map(|(c, k)|server_key.simple_sum(&vec![c.clone(), k.clone()]))
                                .collect()
            }
}



fn shift_rows(state : &AESStateBoolean) -> AESStateBoolean{
    AESStateBoolean { bits: (0..4).map(|col|
        (0..4).map(|row|
            (0..8).map(|i_bit| 
                state.square_getter(row, (col + row) % 4, i_bit).to_owned()
            ).collect()
        ).collect::<Vec<Vec<Ciphertext>>>().concat()
    ).collect::<Vec<Vec<Ciphertext>>>().concat() 
    }
}


fn mix_columns(state : &AESStateBoolean, server_key:&ServerKey) -> AESStateBoolean{
    AESStateBoolean {
        bits : (0..4).map(|col| {
            let mut circuit = LinearCircuit::new(&state.bits[col*32..(col + 1)*32].to_vec());
            circuit.execute_circuit(&server_key, "./src/encrypted_aes/data/mixcolumns2.txt");
            circuit.y
        }).collect::<Vec<Vec<Ciphertext>>>().concat()
    }
}



 fn rot_words_key_expansion(bits : &mut Vec<Ciphertext>){
    assert_eq!(bits.len(), 32);
    bits.rotate_left(8);
}


 fn send_bits_to_nibbles_key_expansion(bits : &Vec<Ciphertext>, server_key : &ServerKey) -> Vec<Ciphertext>{
    assert_eq!(bits.len(), 32);
    let encoding_arithmetic = Encoding::new_canonical(16, (0..16).collect(), 17);

    (0..8)
        .into_par_iter() //comment this line to deactivate parallelization
        .map(|i| bits[i*4..(i+1)*4].to_vec())
        .map(|v| recomposer(&v, &encoding_arithmetic, &server_key))
        .collect()
}


 fn sub_words_key_expansion(nibbles : &Vec<Ciphertext>, server_key : &ServerKey) -> Vec<Ciphertext>{
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
        nibbles_last_row = sub_words_key_expansion(&nibbles_last_row, server_key);

        
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




pub fn encrypted_aes(state: &AESStateBoolean, server_key:&ServerKey, round_keys : &Vec<Vec<Ciphertext>>, client_key_debug : &ClientKey) -> Vec<u8>{
    // Initial round key addition
    let mut state_bool =  add_round_key(state, &round_keys[0], server_key);
    
    let mut state_arith = state_bool.aes_recomposer(&server_key);
    
    //9 full rounds
    for r in 0..9{
        state_arith = sub_bytes(&state_arith, server_key);      

        state_bool = state_arith.aes_decomposer(&server_key);
       

        state_bool = shift_rows(&state_bool);

        state_bool = mix_columns(&state_bool, server_key);

        state_bool = add_round_key(&state_bool, &round_keys[r + 1], server_key);
        
        state_arith = state_bool.aes_recomposer(&server_key);       
    }
    state_arith = sub_bytes(&state_arith, server_key);
    
    state_bool = state_arith.aes_decomposer(&server_key);
    
    state_bool = shift_rows(&state_bool);
    
    state_bool = add_round_key(&state_bool, &round_keys[10], server_key);

    let clear_bits = state_bool.tfhe_decryption_bits(&client_key_debug);

    (0..16).map(|i| 
        clear_bits[i * 8..(i+1) * 8].iter().enumerate().map(|(i, bit)| (bit * (1 << (7 - i))) as u8).sum::<u8>())
        .collect()
}




// pub const _PARAMETERS_40: CustomOddParameters = CustomOddParameters {
//     lwe_dimension: LweDimension(754),
//     glwe_dimension: GlweDimension(1),
//     polynomial_size: PolynomialSize(1024),
//     lwe_noise_distribution:  DynamicDistribution::new_gaussian_from_std_dev(StandardDev(5.0e-6)),
//     glwe_noise_distribution:  DynamicDistribution::new_gaussian_from_std_dev(StandardDev(5.871712650082723e-15)),
//     pbs_base_log: DecompositionBaseLog(23),
//     pbs_level: DecompositionLevelCount(2),
//     ks_base_log: DecompositionBaseLog(4),
//     ks_level: DecompositionLevelCount(3),
//     encryption_key_choice: EncryptionKeyChoice::Big,
// };






pub const PARAMETERS_128: CustomOddParameters = CustomOddParameters {
    lwe_dimension: LweDimension(900),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution:  DynamicDistribution::new_gaussian_from_std_dev(StandardDev(6.8e-7)),
    glwe_noise_distribution:  DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// pub const PARAMETERS_64: CustomOddParameters = CustomOddParameters {
//     lwe_dimension: LweDimension(850),
//     glwe_dimension: GlweDimension(2),
//     polynomial_size: PolynomialSize(1024),
//     lwe_noise_distribution:  DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.65e-6)),
//     glwe_noise_distribution:  DynamicDistribution::new_gaussian_from_std_dev(StandardDev(5e-32)),
//     pbs_base_log: DecompositionBaseLog(26),
//     pbs_level: DecompositionLevelCount(1),
//     ks_base_log: DecompositionBaseLog(8),
//     ks_level: DecompositionLevelCount(5),
//     encryption_key_choice: EncryptionKeyChoice::Big,
// };


pub const PARAMETERS_ORPHEUS: CustomOddParameters = CustomOddParameters {
    lwe_dimension: LweDimension(1421),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution:  DynamicDistribution::new_gaussian_from_std_dev(StandardDev(5.820766091346741e-11)),
    glwe_noise_distribution:  DynamicDistribution::new_gaussian_from_std_dev(StandardDev(7.732042235774039e-16)),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(8),
    ks_level: DecompositionLevelCount(5),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub fn demo_encrypted_aes(number_of_outputs: usize, iv: &String, key: &String, ciphertexts_conventional : Vec<Vec<u8>>) {
    let parameters = PARAMETERS_ORPHEUS;    //HERE SELECT THE PARAMETER SET

    let (client_key, server_key) = gen_keys(&parameters);

    // Convert the key and IV from hexadecimal strings to byte arrays.
    let key_bytes = hex::decode(key).expect("Invalid hex for key");
    let mut iv_bytes : Vec<u64> = hex::decode(iv).expect("Invalid hex for IV").iter().map(|x| *x as u64).collect();

    // Ensure the key and IV are the correct lengths for AES-128
    assert_eq!(key_bytes.len(), 16, "Key must be 16 bytes for AES-128");
    assert_eq!(iv_bytes.len(), 16, "IV must be 16 bytes for AES-128");

    // Encrypt the key
    let encrypted_aes_key = key_bytes.into_iter()
                                                        .map(|x| (0..8)
                                                                            .map(|i| (x >> (7 - i)) % 2)
                                                                            .map(|x| client_key.encrypt_arithmetic(x as u64, &Encoding::parity_encoding()))
                                                                            .collect())
                                                        .collect::<Vec<Vec<Ciphertext>>>()
                                                        .concat();

    let key_expansion_start = Instant::now();
    let encrypted_round_keys = encrypted_key_expansion(encrypted_aes_key, &server_key);
    println!("AES key expansion took: {:?}", key_expansion_start.elapsed());

    let encryption_start = Instant::now();
    for i in 0..number_of_outputs {
        // Treat the IV as a counter and increment it for each output
        let counter_block = iv_bytes.clone();

        // First, send cast everything as boolean for encryption
        let counter_block_bits = counter_block.into_iter()
                .map(|x| (0..8)
                                    .map(|i| (x >> (7 - i)) % 2)
                                    .collect())
                .collect::<Vec<Vec<u64>>>()
                .concat();

        // Encrypt the block (not necessary, we could just provide it as plaintexts but it fits better the original api)
        let state = AESStateBoolean::tfhe_encryption_bits(&counter_block_bits, &client_key);

        let result = encrypted_aes(&state, &server_key, &encrypted_round_keys, &client_key);

        // Check that the fhe computations yielded correct results
        println!("Real result : {:?}", ciphertexts_conventional[i]);
        println!(" FHE result : {:?}", result);
        assert_eq!(result, ciphertexts_conventional[i]);

        // Increment the IV (counter) as a 128-bit value (big-endian)
        increment_iv_u64(&mut iv_bytes);
    }
    println!("AES of {} outputs computed in {:?}", number_of_outputs, encryption_start.elapsed());
}    
