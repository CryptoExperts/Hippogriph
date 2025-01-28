//! Module with the engine definitions.
//!
//! Engines are required to abstract cryptographic notions and efficiently manage memory from the
//! underlying `core_crypto` module.

use tfhe_csprng::generators::DefaultRandomGenerator;

use crate::core_crypto::algorithms::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::CiphertextModulus;
use crate::core_crypto::prelude::Container;
use crate::core_crypto::prelude::ContiguousEntityContainer;
use crate::core_crypto::prelude::EncryptionKeyChoice;
use crate::core_crypto::prelude::LweSize;
use crate::core_crypto::prelude::MonomialDegree;
use crate::core_crypto::prelude::PBSOrder;
use crate::core_crypto::prelude::PlaintextCount;
use crate::odd::prelude::*;
use std::cell::RefCell;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
pub mod bootstrapping;
use crate::core_crypto::commons::generators::{
    DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::core_crypto::commons::math::random::Seeder;
use crate::odd::engine::bootstrapping::{Bootstrapper, ServerKey};
//use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::seeders::new_seeder;

use super::ciphertext::Encoding;


/// Trait to be able to acces thread_local
/// engines in a generic way
pub(crate) trait WithThreadLocalEngine {
    fn with_thread_local_mut<R, F>(func: F) -> R
    where
        F: FnOnce(&mut Self) -> R;
}

// All our thread local engines
// that our exposed types will use internally to implement their methods
thread_local! {
    static ODD_ENGINE: RefCell<OddEngine> = RefCell::new(OddEngine::new());
}

pub struct OddEngine {
    /// A structure containing a single CSPRNG to generate secret key coefficients.
    secret_generator: SecretRandomGenerator<DefaultRandomGenerator>,
    /// A structure containing two CSPRNGs to generate material for encryption like public masks
    /// and secret errors.
    ///
    /// The [`EncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    encryption_generator: EncryptionRandomGenerator<DefaultRandomGenerator>,
    bootstrapper: Bootstrapper,
}

impl WithThreadLocalEngine for OddEngine {
    fn with_thread_local_mut<R, F>(func: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        ODD_ENGINE.with(|engine_cell| func(&mut engine_cell.borrow_mut()))
    }
}

impl OddEngine {
    pub fn create_client_key(&mut self, parameters: CustomOddParameters) -> ClientKey {
        // generate the lwe secret key
        let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            parameters.lwe_dimension,
            &mut self.secret_generator,
        );

        // generate the glwe secret key
        let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            parameters.glwe_dimension,
            parameters.polynomial_size,
            &mut self.secret_generator,
        );

        ClientKey {
            lwe_secret_key,
            glwe_secret_key,
            parameters,
        }
    }

    pub fn create_server_key(&mut self, cks: &ClientKey) -> ServerKey {
        let server_key = self.bootstrapper.new_server_key(cks);

        server_key
    }

    pub fn trivial_encrypt(&mut self, message: u64) -> Ciphertext {
        Ciphertext::Trivial(message)
    }

    fn encryption_from_plaintext(
        &mut self,
        cks: &ClientKey,
        plaintext: Plaintext<u64>,
    ) -> LweCiphertext<Vec<u64>> {
        let (lwe_sk, encryption_noise) = match cks.parameters.encryption_key_choice {
            EncryptionKeyChoice::Big => (
                cks.glwe_secret_key.as_lwe_secret_key(),
                cks.parameters.glwe_noise_distribution,
            ),
            EncryptionKeyChoice::Small => {
                let view = LweSecretKey::from_container(cks.lwe_secret_key.as_ref());
                (view, cks.parameters.lwe_noise_distribution)
            }
        };

        allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            plaintext,
            encryption_noise,
            CiphertextModulus::new_native(),
            &mut self.encryption_generator,
        )
    }

    pub fn encode_message_into_plaintext(
        &mut self,
        message: u64,
        encoding: &Encoding,
    ) -> Plaintext<u64> {
        let zpelem = encoding.get_part_single_value_if_canonical(message);
        let buffer: u128 = (1 << 64) / encoding.get_modulus() as u128 * zpelem as u128;
        Plaintext(buffer as u64)
    }

    pub fn encrypt_arithmetic(
        &mut self,
        message: u64,
        encoding: &Encoding,
        cks: &ClientKey,
    ) -> Ciphertext {
        assert!(message < encoding.get_origin_modulus());

        //  Encode the arithmetic message over Zp
        let plaintext = self.encode_message_into_plaintext(message, encoding);

        let ct = self.encryption_from_plaintext(cks, plaintext);
        Ciphertext::EncodingEncrypted(ct, encoding.clone())
    }

    pub fn decrypt(&mut self, ct: &Ciphertext, cks: &ClientKey) -> u64 {
        let lwe_sk = match cks.parameters.encryption_key_choice {
            EncryptionKeyChoice::Big => cks.glwe_secret_key.as_lwe_secret_key(),
            EncryptionKeyChoice::Small => LweSecretKey::from_container(cks.lwe_secret_key.as_ref()),
        };

        match ct {
            Ciphertext::Trivial(b) => *b,
            Ciphertext::EncodingEncrypted(ciphertext, encoding) => {
                Self::decrypt_arithmetic(&lwe_sk, ciphertext, encoding)
            }
        }
    }

    fn decrypt_arithmetic(
        lwe_sk: &LweSecretKey<&[u64]>,
        ciphertext: &LweCiphertext<Vec<u64>>,
        encoding: &Encoding,
    ) -> u64 {
        // decryption
        let decrypted = decrypt_lwe_ciphertext(&lwe_sk, ciphertext);

        // cast as a u64
        let decrypted_u64 = decrypted.0 as u64;
        // println!("Debug : decrypted : {}", decrypted_u64);

        let divisor: u128 = 1 << 64;
        let divisor_float = divisor as f64;
        let slice: f64 = encoding.get_modulus() as f64 / divisor_float;
        // println!("Debug : decrypted : {}, on Zp : {}", decrypted_u64, decrypted_u64 as f64 / divisor_float * encoding.get_modulus() as f64);

        let floating_result = decrypted_u64 as f64 * slice;

        let closest_integer = floating_result.round() as u64 % encoding.get_modulus();

        for i in 0..encoding.get_origin_modulus() {
            if encoding.is_partition_containing(i, closest_integer) {
                return i;
            }
        }
        panic!("No value in Zo has been found for : {}.", floating_result);
    }

    pub fn measure_noise(&mut self, ct: &Ciphertext, cks: &ClientKey) -> i64 {
        match ct {
            Ciphertext::Trivial(_) => panic!("No error level with trivial ciphertext"),
            Ciphertext::EncodingEncrypted(ciphertext, encoding) => {
                let lwe_sk = match cks.parameters.encryption_key_choice {
                    EncryptionKeyChoice::Big => cks.glwe_secret_key.as_lwe_secret_key(),
                    EncryptionKeyChoice::Small => {
                        LweSecretKey::from_container(cks.lwe_secret_key.as_ref())
                    }
                };
                // decryption
                let decrypted = decrypt_lwe_ciphertext(&lwe_sk, ciphertext);

                // cast as a u64
                let decrypted_u64 = decrypted.0 as u64;
                //println!("Debug : decrypted : {:#034b}", decrypted_u64);

                let divisor: u128 = 1 << 64;
                let divisor_float = divisor as f64;
                let slice: f64 = encoding.get_modulus() as f64 / divisor_float;
                // println!("Debug : decrypted : {}, on Zp : {}", decrypted_u64, decrypted_u64 as f64 / divisor_float * encoding.get_modulus() as f64);

                let floating_result = decrypted_u64 as f64 * slice;

                let closest_integer = floating_result.round() as u64 % encoding.get_modulus();

                // println!("Closest integer : {}", closest_integer);

                let mut noise = closest_integer as f64 - floating_result;
                if noise.abs() > encoding.get_modulus() as f64 / 2.0 {
                    noise = encoding.get_modulus() as f64 - noise.abs()
                }

                //remettre le bruit dans Zq
                let noise_int = (noise * (1u128 << 64) as f64).round() as i64;
                noise_int
            }
        }
    }

    pub fn test_mvb(&mut self, ct: &GlweCiphertext<Vec<u64>>, client_key: &ClientKey) {
        for i in 0..client_key.parameters.polynomial_size.0 {
            let mut output_lwe = LweCiphertext::new(
                0,
                LweSize(
                    client_key.parameters.glwe_dimension.0
                        * client_key.parameters.polynomial_size.0
                        + 1,
                ),
                CiphertextModulus::new_native(),
            );
            extract_lwe_sample_from_glwe_ciphertext(ct, &mut output_lwe, MonomialDegree(i));
            let decrypted = decrypt_lwe_ciphertext(
                &client_key.glwe_secret_key.as_lwe_secret_key(),
                &output_lwe,
            );
            println!(
                "{} -> {}",
                decrypted.0,
                decrypted.0 as f64 / (1u64 << 32) as f64 * 17f64
            );
        }
    }
}

////// C'est ici que ça se passe !
///

impl OddEngine {
    pub fn exec_gadget_with_extraction(
        &mut self,
        enc_in: &Vec<Encoding>,
        enc_inter: &Encoding,
        enc_out: &Encoding,
        input: &Vec<Ciphertext>,
        server_key: &ServerKey,
    ) -> Ciphertext {
        let size = match server_key.pbs_order {
            PBSOrder::KeyswitchBootstrap => server_key
                .key_switching_key
                .input_key_lwe_dimension()
                .to_lwe_size(),
            PBSOrder::BootstrapKeyswitch => server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        };

        let mut buffer_lwe_before_pbs =
            LweCiphertext::new(0u64, size, CiphertextModulus::new_native());

        let bootstrapper = &mut self.bootstrapper;

        // compute the sum
        input.iter().for_each(|x| match x {
            Ciphertext::EncodingEncrypted(x_ct, _) => {
                lwe_ciphertext_add_assign(&mut buffer_lwe_before_pbs, &x_ct);
            }
            Ciphertext::Trivial(_) => panic!("Not yet implemented with trivial ciphertexts"),
        });

        // compute the bootstrap and the key switch
        bootstrapper.apply_bootstrapping_pattern(
            buffer_lwe_before_pbs,
            enc_inter,
            enc_out,
            server_key,
        )
    }

    pub fn apply_lut(
        &mut self,
        input: &Ciphertext,
        output_encoding: &Encoding,
        f: &dyn Fn(u64) -> u64,
        server_key: &ServerKey,
    ) -> Ciphertext {
        match input {
            Ciphertext::EncodingEncrypted(c, enc_in) => {
                let bootstrapper = &mut self.bootstrapper;
                let enc_inter = enc_in.apply_lut_to_encoding(f);
                bootstrapper.apply_bootstrapping_pattern(
                    c.clone(),
                    &enc_inter,
                    output_encoding,
                    server_key,
                )
            }
            _ => panic!(),
        }
    }

    pub fn mvb(
        &mut self,
        input: &Ciphertext,
        output_encodings: &Vec<Encoding>,
        lut_fis: &Vec<Vec<u64>>,
        server_key: &ServerKey,
    ) -> Vec<Ciphertext> {
        match input {
            Ciphertext::EncodingEncrypted(c, input_encoding) => {
                let bootstrapper = &mut self.bootstrapper;
                match server_key.pbs_order {
                    PBSOrder::BootstrapKeyswitch => {
                        let cis = bootstrapper.mvb_bootstrap(
                            c.clone(),
                            input_encoding,
                            output_encodings,
                            lut_fis,
                            server_key,
                        );
                        //keyswitching
                        cis.iter()
                            .map(|ci| server_key.keyswitch(ci))
                            .zip(output_encodings)
                            .map(|(ci, enc_i)| Ciphertext::EncodingEncrypted(ci, enc_i.clone()))
                            .collect()
                    }
                    PBSOrder::KeyswitchBootstrap => {
                        let c_after_ks = server_key.keyswitch(c);
                        let cis: Vec<LweCiphertext<Vec<u64>>> = bootstrapper.mvb_bootstrap(
                            c_after_ks,
                            input_encoding,
                            output_encodings,
                            lut_fis,
                            server_key,
                        );
                        cis.iter()
                            .zip(output_encodings)
                            .map(|(ci, enc_i)| {
                                Ciphertext::EncodingEncrypted(ci.clone(), enc_i.clone())
                            })
                            .collect()
                    }
                }
            }
            _ => panic!(),
        }
    }

    pub fn decrypt_glwe_with_builtin_function<OutputCont>(
        client_key_debug: &ClientKey,
        glwe_ciphertext: &GlweCiphertext<OutputCont>,
    ) where
        OutputCont: Container<Element = u64>,
    {
        let mut plaintext_list =
            PlaintextList::new(0u64, PlaintextCount(glwe_ciphertext.polynomial_size().0));
        decrypt_glwe_ciphertext(
            &client_key_debug.glwe_secret_key,
            &glwe_ciphertext,
            &mut plaintext_list,
        );
        plaintext_list.iter().for_each(|plaintext| {
            println!(
                "{:032b} = {} / {}",
                plaintext.0,
                (*plaintext.0 as f64 / (1u64 << 32) as f64 * 5.0).round(),
                plaintext.0
            )
        });
    }

    pub fn compute_common_factor(
        &mut self,
        ciphertext: &Ciphertext,
        enc_out: &Encoding,
        server_key: &ServerKey,
    ) -> GlweCiphertextOwned<u64> {
        let bootstrapper = &mut self.bootstrapper;

        match ciphertext {
            Ciphertext::EncodingEncrypted(lwe_ciphertext, _) => {
                let c_after_ks = server_key.keyswitch(lwe_ciphertext);

                bootstrapper.bootstrap_common_factor(&c_after_ks, enc_out, &server_key)
            }
            Ciphertext::Trivial(_) => panic!(),
        }
    }

    pub fn simple_tree_bootstrapping(
        &mut self,
        common_factor: &GlweCiphertextOwned<u64>,
        inputs: &Vec<Ciphertext>,
        encoding_out: &Encoding,
        t: u64,
        lut_fi: Vec<u64>,
        server_key: &ServerKey,
        client_key_debug: &ClientKey,
        log: bool,
    ) -> Ciphertext {
        let c_0 = inputs[1].clone();
        match c_0 {
            Ciphertext::EncodingEncrypted(_, encoding_in_0) => {
                let bootstrapper = &mut self.bootstrapper;

                let o_0 = encoding_in_0.get_origin_modulus();

                let first_functions: Vec<Vec<u64>> = (0..t / o_0)
                    .map(|j: u64| (0..o_0).map(|x| lut_fi[(x + j * o_0) as usize]).collect())
                    .collect(); // x \in [0, o_0[

                match server_key.pbs_order {
                    PBSOrder::BootstrapKeyswitch => {
                        panic!()
                    }
                    PBSOrder::KeyswitchBootstrap => {
                        // No keyswitch here, because this part jas been taken part while bootstrapping the common factor

                        let first_ciphertexts = bootstrapper
                            .mvb_bootstrap_with_common_factor_given(
                                &common_factor,
                                &encoding_in_0,
                                &vec![encoding_out.clone(); (t / o_0).try_into().unwrap()],
                                &first_functions,
                                &server_key,
                                &client_key_debug,
                            );
                        if log {
                            println!(
                                "TIMING POST_MVB_TREE ? {:?}",
                                SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
                            );
                        }
                        
                        let next_accumulator = bootstrapper.pack_into_new_accumulator(
                            first_ciphertexts,
                            server_key,
                            encoding_in_0.get_modulus(),
                        );
                        if log {
                            println!(
                                "TIMING POST_PACKING_TREE ? {:?}",
                                SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
                            );
                        }


                        //for now, only depth-2 trees

                        let c_1 = inputs[0].clone();
                        match c_1 {
                            Ciphertext::EncodingEncrypted(lwe_c_1, _) => {
                                //we assume that they both hve the same input encoding
                                let lwe_c_1_after_ks = server_key.keyswitch(&lwe_c_1);
                                if log {
                                    println!(
                                        "TIMING POST_SECOND_KEYSWITCH_TREE ? {:?}",
                                        SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
                                    );
                                }

                                let final_lwe = bootstrapper.bootstrap(
                                    &lwe_c_1_after_ks,
                                    &next_accumulator,
                                    server_key,
                                );
                                if log {
                                    println!(
                                        "TIMING POST_SIMPLE_BOOTSTRAPPING_IN_TREE ? {:?}",
                                        SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
                                    );
                                }

                                Ciphertext::EncodingEncrypted(final_lwe, encoding_out.clone())
                            }
                            _ => panic!(),
                        }
                    }
                }
            }
            Ciphertext::Trivial(_) => {
                panic!()
            }
        }
    }

    pub fn encoding_switching_mul_constant(
        &mut self,
        input: &Ciphertext,
        coefficient: u64,
        server_key: &ServerKey,
    ) -> Ciphertext {
        let size = match server_key.pbs_order {
            PBSOrder::KeyswitchBootstrap => server_key
                .key_switching_key
                .input_key_lwe_dimension()
                .to_lwe_size(),
            PBSOrder::BootstrapKeyswitch => server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        };
        let mut result = LweCiphertext::new(0u64, size, CiphertextModulus::new_native());
        // compute the product with the coefficient
        let c = Cleartext(coefficient);
        match input {
            Ciphertext::EncodingEncrypted(x_ct, encoding) => {
                lwe_ciphertext_cleartext_mul(&mut result, &x_ct, c);
                let new_encoding = encoding.multiply_encoding_by_constant(coefficient);
                Ciphertext::EncodingEncrypted(result, new_encoding)
            }
            Ciphertext::Trivial(_) => {
                panic!("Error : casting a trivial ciphertext ! ");
            }
        }
    }

    // Warning : To use only  with similar encodings!
    pub fn simple_sum(&mut self, input: &Vec<Ciphertext>, server_key: &ServerKey) -> Ciphertext {
        let size = match server_key.pbs_order {
            PBSOrder::KeyswitchBootstrap => server_key
                .key_switching_key
                .input_key_lwe_dimension()
                .to_lwe_size(),
            PBSOrder::BootstrapKeyswitch => server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        };

        let mut result = LweCiphertext::new(0u64, size, CiphertextModulus::new_native());
        input.iter().for_each(|x| match x {
            Ciphertext::EncodingEncrypted(x_ct, _) => {
                lwe_ciphertext_add_assign(&mut result, x_ct);
            }
            Ciphertext::Trivial(_) => {
                panic!("simple_sum not yet implemented with plaintexts")
            }
        });
        let same_encoding = match &input[0] {
            Ciphertext::EncodingEncrypted(_, enc) => enc,
            _ => panic!(),
        };
        Ciphertext::EncodingEncrypted(result, same_encoding.to_owned())
    }

    pub fn simple_plaintext_sum(
        &mut self,
        input: &Ciphertext,
        constant: u64,
        modulus: u64,
        server_key: &ServerKey,
    ) -> Ciphertext {
        let size = match server_key.pbs_order {
            PBSOrder::KeyswitchBootstrap => server_key
                .key_switching_key
                .input_key_lwe_dimension()
                .to_lwe_size(),
            PBSOrder::BootstrapKeyswitch => server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        };

        let mut result = LweCiphertext::new(0u64, size, CiphertextModulus::new_native());
        let buffer_value: u128 = (1 << 64) / modulus as u128 * constant as u128;
        let value = Plaintext(buffer_value as u64);
        match input {
            Ciphertext::EncodingEncrypted(x_ct, encoding) => {
                lwe_ciphertext_plaintext_add_assign(&mut result, value);
                lwe_ciphertext_add_assign(&mut result, x_ct);
                Ciphertext::EncodingEncrypted(result, encoding.clone())
            }
            Ciphertext::Trivial(_) => {
                panic!("don't use trivial encryption in this context")
            }
        }
    }

    pub fn simple_mul_constant(
        &mut self,
        input: &Ciphertext,
        constant: u64,
        modulus: u64,
        server_key: &ServerKey,
    ) -> Ciphertext {
        let size = match server_key.pbs_order {
            PBSOrder::KeyswitchBootstrap => server_key
                .key_switching_key
                .input_key_lwe_dimension()
                .to_lwe_size(),
            PBSOrder::BootstrapKeyswitch => server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        };

        let mut result = LweCiphertext::new(0u64, size, CiphertextModulus::new_native());
        let coeff = Cleartext(constant % modulus);
        match input {
            Ciphertext::EncodingEncrypted(x_ct, encoding) => {
                lwe_ciphertext_cleartext_mul(&mut result, x_ct, coeff);
                Ciphertext::EncodingEncrypted(result, encoding.clone())
            }
            Ciphertext::Trivial(_) => {
                panic!("don't use trivial encryption in this context")
            }
        }
    }

    pub fn encoding_switching_sum_constant(
        &mut self,
        input: &Ciphertext,
        constant: u64,
        modulus: u64,
        server_key: &ServerKey,
    ) -> Ciphertext {
        let size = match server_key.pbs_order {
            PBSOrder::KeyswitchBootstrap => server_key
                .key_switching_key
                .input_key_lwe_dimension()
                .to_lwe_size(),
            PBSOrder::BootstrapKeyswitch => server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        };

        let mut result = LweCiphertext::new(0u64, size, CiphertextModulus::new_native());
        let buffer_value: u128 = (1 << 64) / modulus as u128 * constant as u128;
        let value = Plaintext(buffer_value as u64);
        match input {
            Ciphertext::EncodingEncrypted(x_ct, encoding) => {
                lwe_ciphertext_plaintext_add_assign(&mut result, value);
                lwe_ciphertext_add_assign(&mut result, x_ct);
                Ciphertext::EncodingEncrypted(result, encoding.add_constant(constant))
            }
            Ciphertext::Trivial(_) => {
                panic!("don't use trivial encryption in this context")
            }
        }
    }
}


//////////

impl Default for OddEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl OddEngine {
    pub fn new() -> Self {
        let mut root_seeder = new_seeder();

        Self::new_from_seeder(root_seeder.as_mut())
    }

    pub fn new_from_seeder(root_seeder: &mut dyn Seeder) -> Self {
        let mut deterministic_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(root_seeder.seed());

        // Note that the operands are evaluated from left to right for Rust Struct expressions
        // See: https://doc.rust-lang.org/stable/reference/expressions.html?highlight=left#evaluation-order-of-operands
        Self {
            secret_generator: SecretRandomGenerator::<_>::new(deterministic_seeder.seed()),
            encryption_generator: EncryptionRandomGenerator::<_>::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            ),
            bootstrapper: Bootstrapper::new(&mut deterministic_seeder),
        }
    }
}
