use std::{fs::{File, OpenOptions}, time::{Instant, SystemTime, UNIX_EPOCH}};
use std::io::{self, Write};

use clear::clear_sub_bytes;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use tfhe::{core_crypto::prelude::DynamicDistribution, odd::prelude::*};

use crate::aes::aes_utils::{pretty_print_clear, u8_to_vec_bool_integer};

use self::{aes_utils::{key_expansion, pretty_print_nibbles, u8_to_vec_bool, vec_bool_to_u8}, casts::{decomposer, recomposer}, clear::clear_mixcolumns, linear_circuit::LinearCircuit};

mod aes_utils;
mod linear_circuit;
mod casts;
mod clear;


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

    pub fn aes_recomposer(&self, server_key : &ServerKey, client_key_debug : &ClientKey)-> AESStateArithmetic{
        let encoding_arithmetic = Encoding::new_canonical(16, (0..16).collect(), 17);
        AESStateArithmetic{
            nibbles : (0..32)
                    .into_par_iter() //comment this line to deactivate parallelization
                    .map(|i| self.bits[i*4..(i+1)*4].to_vec())
                    .map(|v| recomposer(&v, &encoding_arithmetic, &server_key, &client_key_debug))
                    .collect(),
            encoding : encoding_arithmetic
        }
    }

}



pub struct AESStateArithmetic{
    pub nibbles : Vec<Ciphertext>, //each nibble is 4-bits long
    pub encoding : Encoding
}



impl AESStateArithmetic{

    pub fn aes_decomposer(&self, server_key : &ServerKey, client_key_debug : &ClientKey) -> AESStateBoolean{
        AESStateBoolean{
            bits : self.nibbles
            //.iter()
            .par_iter() //select the line to select parallelization
            .map(|x| decomposer(x, &Encoding::parity_encoding(), server_key, client_key_debug))
            .collect::<Vec<Vec<Ciphertext>>>()
            .concat()
        }
     }

}



fn sub_bytes(state : &AESStateArithmetic, server_key:&ServerKey, client_key_debug : &ClientKey) -> AESStateArithmetic{
    assert_eq!(state.nibbles.len(), 32);
    AESStateArithmetic{
        nibbles : (0..16)
                .into_par_iter()    //comment this line to activate parallelisation
                .map(|i| (i, state.nibbles[i*2..(i+1)*2].to_vec()))
                .map(|(i, v)| server_key.full_tree_bootstrapping(&v, 
                                                                        &vec![state.encoding.clone();2],
                                                                        256,
                                                                        &clear_sub_bytes, 
                                                                        client_key_debug,
                                                                        i == 0))
                .collect::<Vec<Vec<Ciphertext>>>()
                .concat(),
        encoding : state.encoding.clone()
    }
}




fn add_round_key(state : &AESStateBoolean, round_key : &Vec<bool>, server_key:&ServerKey) -> AESStateBoolean{
    assert_eq!(state.bits.len(), 128);
    assert_eq!(round_key.len(), 128);
    AESStateBoolean { bits: state.bits.iter()
                                .zip(round_key)
                                .map(|(c, k)| if *k {server_key.simple_plaintext_sum(c, 1, 2)} else {c.to_owned()})
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


fn mix_columns(state : &AESStateBoolean, server_key:&ServerKey, client_key_debug : &ClientKey) -> AESStateBoolean{
    AESStateBoolean {
        bits : (0..4).map(|col| {
            let mut circuit = LinearCircuit::new(&state.bits[col*32..(col + 1)*32].to_vec());
            circuit.execute_circuit(&server_key, "./src/aes/data/mixcolumns2.txt", &client_key_debug);
            circuit.y
        }).collect::<Vec<Vec<Ciphertext>>>().concat()
    }
}


pub fn run_aes(state: &AESStateBoolean, server_key:&ServerKey, aes_key : Vec<bool>, client_key_debug : &ClientKey) -> AESStateBoolean{
    //Debug
    let print_debug = |state : &AESStateBoolean, expected : &str|{
        let result_debug = state.tfhe_decryption_bits(&client_key_debug);
        pretty_print_clear(&result_debug);
        println!("Expected\n{}", expected);
        println!();
    };


    let print_debug_arith = |state_arith: &AESStateArithmetic, expected : &str|{
        let result = state_arith.nibbles.iter()
                                        .map(|nib| client_key_debug.decrypt(&nib))
                                        .collect();
        pretty_print_nibbles(&result);
        println!("Expected\n{}", expected);
        println!();
    };


    let expected = vec![
        "00 10 20 30 40 50 60 70 80 90 a0 b0 c0 d0 e0 f0",
        "89 d8 10 e8 85 5a ce 68 2d 18 43 d8 cb 12 8f e4",
        "49 15 59 8f 55 e5 d7 a0 da ca 94 fa 1f 0a 63 f7",
        "fa 63 6a 28 25 b3 39 c9 40 66 8a 31 57 24 4d 17",
        "24 72 40 23 69 66 b3 fa 6e d2 75 32 88 42 5b 6c",
        "c8 16 77 bc 9b 7a c9 3b 25 02 79 92 b0 26 19 96",
        "c6 2f e1 09 f7 5e ed c3 cc 79 39 5d 84 f9 cf 5d",
        "d1 87 6c 0f 79 c4 30 0a b4 55 94 ad d6 6f f4 1f",
        "fd e3 ba d2 05 e5 d0 d7 35 47 96 4e f1 fe 37 f1",
        "bd 6e 7c 3d f2 b5 77 9e 0b 61 21 6e 8b 10 b6 89"
    ];

    // Key Expansion
    let round_keys = key_expansion(aes_key);

    // Initial round key addition
    let mut state_bool =  add_round_key(state, &round_keys[0], server_key);
    print_debug(&state_bool, expected[0]); 
    
    let mut state_arith = state_bool.aes_recomposer(&server_key, &client_key_debug);
    println!("After recomposition :");
    print_debug_arith(&state_arith, expected[0]);
    
    //9 full rounds
    for r in 0..9{
        println!("TIMING START_ROUND {} {:?}", r+1, SystemTime::now().duration_since(UNIX_EPOCH).unwrap());
        println!("Round {}", r + 1);
        state_arith = sub_bytes(&state_arith, server_key, client_key_debug);
        println!("TIMING POST_SUB_BYTES {} {:?}", r+1, SystemTime::now().duration_since(UNIX_EPOCH).unwrap());
        print_debug_arith(&state_arith, "");
        

        state_bool = state_arith.aes_decomposer(&server_key, &client_key_debug);
        println!("TIMING POST_BOOLEAN_DECOMPOSITION {} {:?}", r+1, SystemTime::now().duration_since(UNIX_EPOCH).unwrap());
        print_debug_arith(&state_arith, "");
        

        state_bool = shift_rows(&state_bool);
        println!("TIMING POST_SHIFT_ROWS {} {:?}", r+1, SystemTime::now().duration_since(UNIX_EPOCH).unwrap());

        state_bool = mix_columns(&state_bool, server_key, client_key_debug);
        println!("TIMING POST_MIX_COLUMNS {} {:?}", r+1, SystemTime::now().duration_since(UNIX_EPOCH).unwrap());

        state_bool = add_round_key(&state_bool, &round_keys[r + 1], server_key);
        println!("TIMING POST_ADD_ROUND_KEYS {} {:?}", r+1, SystemTime::now().duration_since(UNIX_EPOCH).unwrap());
        
        print_debug(&state_bool, expected[r+1]);


        state_arith = state_bool.aes_recomposer(&server_key, &client_key_debug);
        println!("TIMING POST_BOOLEAN_RECOMPOSITION {} {:?}", r+1, SystemTime::now().duration_since(UNIX_EPOCH).unwrap());
        print_debug_arith(&state_arith, expected[r+1]);
        
    }
    state_arith = sub_bytes(&state_arith, server_key, client_key_debug);
    
    
    state_bool = state_arith.aes_decomposer(&server_key, &client_key_debug);
    

    state_bool = shift_rows(&state_bool);
    state_bool = add_round_key(&state_bool, &round_keys[10], server_key);
    
    state_bool
}




pub const PARAMETERS_40: CustomOddParameters = CustomOddParameters {
    lwe_dimension: LweDimension(754),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution:  DynamicDistribution::new_gaussian_from_std_dev(StandardDev(5.0e-8)),
    glwe_noise_distribution:  DynamicDistribution::new_gaussian_from_std_dev(StandardDev(5.871712650082723e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    encryption_key_choice: EncryptionKeyChoice::Big,
};




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


pub fn  demo_aes(){
    println!("TIMING START_ALL {:?}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap());


    let parameters = PARAMETERS_40;    //HERE SELECT THE PARAMETER SET


    let (client_key, server_key) = gen_keys(&parameters);

    let plaintext = vec![
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff,
    ];
    let aes_key = [
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    ];

    let plaintext_bits = plaintext.iter().map(|byte| u8_to_vec_bool_integer(*byte)).collect::<Vec<Vec<u64>>>().concat();
    let aes_key_bits = aes_key.iter().map(|byte| u8_to_vec_bool(*byte)).collect::<Vec<Vec<bool>>>().concat();

    let state = AESStateBoolean::tfhe_encryption_bits(&plaintext_bits, &client_key);

    let start = Instant::now();
    let result = run_aes(&state, &server_key, aes_key_bits, &client_key);
    let stop = start.elapsed();
    println!("Time elapsed : {:?}", stop);


    let result_clear = result.tfhe_decryption_bits(&client_key);
    let mut output = String::new();
    (0..16).for_each(|i| {
        output.push_str(&format!("{:02x} ", vec_bool_to_u8(&result_clear[i * 8..(i + 1) * 8].to_vec())));
    });
    println!("{}", output);
    
    let expected = String::from("69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a ");
    println!("Expected:");
    println!("{}", expected);
    //assert_eq!(output, expected);
}
    
