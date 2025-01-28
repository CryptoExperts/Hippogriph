//! # Description
//! This library revisits the implementation of the tfhe scheme to support odd plaintext moduli
//! TOWRITE
//!
//!
//!
//! # Quick Example
//! TOWRITE


use crate::odd::client_key::ClientKey;
use crate::odd::server_key::ServerKey;
#[cfg(test)]
use rand::Rng;

use self::prelude::CustomOddParameters;


pub mod ciphertext;
pub mod client_key;
pub mod engine;
pub mod parameters;
pub mod prelude;
pub mod server_key;


/// tool to generate random integers
#[cfg(test)]
pub(crate) fn random_integer() -> u64 {
    // create a random generator
    let mut rng = rand::thread_rng();

    // generate a random u32
    rng.gen::<u64>()
}

/// Generate a couple of client and server keys with provided parameters:
/// 
/// The client is the one generating both keys.
/// * the client key is used to encrypt and decrypt and has to be kept secret;
/// * the server key is used to perform homomorphic operations on the server side and it is
/// meant to be published (the client sends it to the server).
///
pub fn gen_keys(parameters : &CustomOddParameters) -> (ClientKey, ServerKey) {
    // generate the client key
    let cks = ClientKey::new(&parameters);

    // generate the server key
    let sks = ServerKey::new(&cks);

    // return
    (cks, sks)
}
