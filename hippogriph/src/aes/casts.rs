use tfhe::odd::prelude::*;



pub fn recomposer(bits : &Vec<Ciphertext>, encoding_out : &Encoding, server_key : &ServerKey, client_key_debug : &ClientKey)->Ciphertext{
    let new_p = encoding_out.get_modulus();
    let inv3_mod_p = match new_p {
        17 => 6,
        _ => panic!()
    };
    let negacyclic_encodings_binary = vec![
        Encoding::new_canonical(2, vec![new_p - 4, 4], new_p),
        Encoding::new_canonical(2, vec![new_p - 2, 2], new_p),
        Encoding::new_canonical(2, vec![new_p - 1, 1], new_p),
        Encoding::new_canonical(2, vec![new_p - 3, 3], new_p),
    ];
    let constants_to_sum = vec![4, 2, 1, 3];
    let mut bits_with_new_modulo : Vec<Ciphertext> = bits.iter()
                                        .zip(negacyclic_encodings_binary)
                                        .map(|(c, e)| 
                                            server_key.encoding_switching_lut(c, &e)
                                        )
                                        .zip(constants_to_sum)
                                        .map(|(c, constant)|server_key.encoding_switching_sum_constant(&c, constant, new_p))
                                        .collect();
    // just change the enncoding of the lat one (minimal noise overhead of x 3)
    bits_with_new_modulo[3] = server_key.encoding_switching_mul_constant(&bits_with_new_modulo[3], 3);
    let l = bits.len();
    assert_eq!(l, 4);
    let result = server_key.simple_sum(&bits_with_new_modulo);
    match result{
        Ciphertext::EncodingEncrypted(c, _) =>{Ciphertext::EncodingEncrypted(c, encoding_out.clone())},
        _ => {panic!()}
    }          
}




pub fn decomposer(input : &Ciphertext, encoding_out : &Encoding, server_key : &ServerKey, client_key_debug : &ClientKey) -> Vec<Ciphertext>{
    let encoding_in = match input{
        Ciphertext::EncodingEncrypted(_, encoding_in) => encoding_in,
        _ => panic!("No encoding with trivial ciphertexts")
    };
    let mut o = encoding_in.get_origin_modulus();
    assert!(o & (o-1) == 0); //check that o is a power of two
    //count the number of bits
    let mut l = 0;
    let mut functions: Vec<Box<dyn Fn(u64) -> u64>> = vec![];
 
    while o > 1{
        functions.push(Box::new(move |x : u64| -> u64 {(x >> l) % 2}));
        o = o / 2;
        l += 1;
    }


    let mut result = server_key.mvb(
        &input, 
        &vec![encoding_out.clone();l], 
        &functions,
    );

    result.reverse();
    result
}
