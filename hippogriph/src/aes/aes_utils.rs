use tfhe::odd::prelude::*;

static RC: [u64;11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

static AES_SBOX: [[u8;16];16] = [ [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
                                  [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
                                  [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
                                  [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
                                  [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
                                  [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
                                  [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
                                  [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
                                  [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
                                  [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
                                  [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
                                  [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
                                  [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
                                  [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
                                  [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
                                  [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16] ];


pub fn pretty_print_encrypted(v : &Vec<Ciphertext>, client_key : &ClientKey, modulus: u64){
    let v = match v.len() % 8 {
        0 => v.to_owned(),
        _ => {
            println!("Trimming end bits...");
            v[..v.len() - v.len() % 8].to_vec()
        }
    };
    let result_debug = v.iter().map(|c| client_key.decrypt(c)).collect();
    pretty_print_clear(&result_debug);
}


pub fn pretty_print_clear(v : &Vec<u64>){
    if v.len() % 8 != 0{
        println!("Trimming end bits...");
        let v = v[..(v.len() / 8) * 8].to_vec();
    }    
    let l = v.len() / 8;
    (0..l).for_each(|i: usize| print!("{:02x} ", vec_bool_to_u8(&v[i * 8..(i + 1) * 8].to_vec())));
    println!()
}

pub fn pretty_print_nibbles(v : &Vec<u64>){
    v.iter().enumerate().for_each(|(i, x)| {print!("{:x}", x); if i % 2 == 1 {print!(" ")}});
    println!();
}

fn vec_bool_to_u64(v : &Vec<bool>) -> u64{
    assert_eq!(v.len(), 32);
    v.iter().enumerate().map(|(i, b)| if *b {1 << (31 - i)} else {0}).sum()
}


fn u64_to_vec_bool(x : u64) -> Vec<bool>{
    (0..32).map(|i| (x >> (31 - i)) % 2 == 1).collect()
}

pub fn vec_bool_to_u8(v : &Vec<u64>) -> u8{
    assert_eq!(v.len(), 8);
    v.iter().enumerate().map(|(i, b)| if *b == 1 {1 << (7 - i)} else {0}).sum()
}


pub fn u8_to_vec_bool(x : u8) -> Vec<bool>{
    (0..8).map(|i| (x >> (7 - i)) % 2 == 1).collect()
}


pub fn u8_to_vec_bool_integer(x : u8) -> Vec<u64>{
    (0..8).map(|i| (x as u64 >> (7 - i)) % 2).collect::<Vec<u64>>()
}


fn rot_word(x : u64) -> u64{
    let mut v = u64_to_vec_bool(x);
    v.rotate_left(8);
    vec_bool_to_u64(&v)
}


fn sub_word(x : u64) -> u64{
    let bytes : Vec<u8> = (0..4).map(|i| (x >> (8 * (3 - i)) % 256) as u8).collect();
    let bytes_subs : Vec<u8> = bytes.iter().map(|o| substitute(*o)).collect();
    bytes_subs.iter().enumerate().map(|(i, o)| (*o as u64)  << (8 * (3 - i))).sum()
}


fn rcon(i : usize) -> u64{
    RC[i] << 24
}


fn substitute(o : u8) -> u8{
    let upper_nibble = o >> 4;
    let lower_nibble = o % 16;
    AES_SBOX[upper_nibble as usize][lower_nibble as usize]
}


pub fn key_expansion(aes_key : Vec<bool>) -> Vec<Vec<bool>>{
    let n = 4;  // N
    let original_key_words: Vec<u64> = (0..n).map(|i| vec_bool_to_u64(&aes_key[i * 32..(i + 1) * 32].to_vec())).collect();
    let r = 11; //R
    let mut round_keys_words : Vec<u64> = vec![];

    for i in 0..n * r{
        if i < n{
            round_keys_words.push(original_key_words[i]);
        }
        else if i % n == 0{
            round_keys_words.push(round_keys_words[i - n] ^ sub_word(rot_word(round_keys_words[i-1])) ^ rcon(i / n));
        }
        else if (n > 6) & (i % n == 4){
            round_keys_words.push(round_keys_words[i-n] ^ sub_word(round_keys_words[i - 1]));
        }
        else{
            round_keys_words.push(round_keys_words[i - n] ^ round_keys_words[i - 1]);
        }
    }

    let mut round_keys : Vec<Vec<bool>> = vec![];
    for i in 0..r{
        let mut key_i = vec![];
        for j in 0..n{
            key_i = [key_i, u64_to_vec_bool(round_keys_words[i * n + j])].concat();
        }
        round_keys.push(key_i)
    }
    round_keys
}



#[test]
fn test_key_expansion(){
    let key = vec![true;128];
    let round_keys = key_expansion(key);

    
    let pretty_print = |x : Vec<bool>|{
        assert_eq!(x.len(), 128);
        let mut bytes: Vec<u8> = vec![];
        for i in 0..128/8{
            bytes.push(x[i * 8..(i+1) * 8].iter().enumerate().map(|(i, b)| if *b {1 << (7 - i)} else {0}).sum())
        }
        bytes.iter().for_each(|b| print!("{:02x} ", *b));
    };

    for round_key in round_keys{
        pretty_print(round_key);
        println!();
    }
    // ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
    // e8 e9 e9 e9 17 16 16 16 e8 e9 e9 e9 17 16 16 16 
    // ad ae ae 19 ba b8 b8 0f 52 51 51 e6 45 47 47 f0 
    // 09 0e 22 77 b3 b6 9a 78 e1 e7 cb 9e a4 a0 8c 6e 
    // e1 6a bd 3e 52 dc 27 46 b3 3b ec d8 17 9b 60 b6 
    // e5 ba f3 ce b7 66 d4 88 04 5d 38 50 13 c6 58 e6 
    // 71 d0 7d b3 c6 b6 a9 3b c2 eb 91 6b d1 2d c9 8d 
    // e9 0d 20 8d 2f bb 89 b6 ed 50 18 dd 3c 7d d1 50 
    // 96 33 73 66 b9 88 fa d0 54 d8 e2 0d 68 a5 33 5d 
    // 8b f0 3f 23 32 78 c5 f3 66 a0 27 fe 0e 05 14 a3 
    // d6 0a 35 88 e4 72 f0 7b 82 d2 d7 85 8c d7 c3 26 
}