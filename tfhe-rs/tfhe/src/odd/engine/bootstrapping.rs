#![allow(non_snake_case)] 


use crate::core_crypto::prelude::{CiphertextModulus, Container, ContiguousEntityContainer, ContiguousEntityContainerMut, Fft, MonomialDegree, PBSOrder, PlaintextCount};
use crate::odd::engine::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign;
use crate::odd::engine::slice_algorithms::slice_wrapping_add_assign;
use crate::odd::prelude::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::generators::{DeterministicSeeder, EncryptionRandomGenerator};
use crate::core_crypto::commons::math::random::{DefaultRandomGenerator, Seeder};
use crate::core_crypto::entities::*;

use self::polynomial_algorithms::polynomial_karatsuba_wrapping_mul;


/////Accumulator used in the BlindRotate part of the bootstrapping
type Accumulator = Vec<u64>;


/// Memory used as buffer for the bootstrap
///
/// It contains contiguous chunk which is then sliced and converted
/// into core's View types.
#[derive(Default)]
pub struct Memory {
    buffer: Vec<u64>,
}

pub struct BuffersRef<'a> {
    pub(crate) lookup_table: GlweCiphertextMutView<'a, u64>,
    // For the intermediate keyswitch result in the case of a big ciphertext
    pub(crate) buffer_lwe_after_ks: LweCiphertextMutView<'a, u64>,
    // For the intermediate PBS result in the case of a smallciphertext
    pub(crate) buffer_lwe_after_pbs: LweCiphertextMutView<'a, u64>,
}


impl Memory {
    //generate the vector of values to fill in each window gor given input and output encodings in simple bootstrapping
    pub fn create_accumulator(encoding_in : &Encoding, encoding_out : &Encoding) -> Accumulator{
        assert!(encoding_in.is_valid());
        assert!(encoding_out.is_canonical());
        let p = encoding_in.get_modulus();
        assert!(p % 2 == 1);
        let mut accu : Accumulator = vec![0;p.try_into().unwrap()];
        for k  in 0..p{ //k is a ZpElem
            if k % 2 == 0{
                //finding the ZoElem i corresponding to this encoding in
                let i = encoding_in.inverse_encoding(k / 2);
                //Finding the new ZpElem corresponding to i in encoding out
                accu[k as usize] = match i{
                    Some(i) => encoding_out.get_part_single_value_if_canonical(i),
                    None => 0
                };
            }
            else{
                //finding the ZoElem i corresponding to this encoding in
                let i = encoding_in.inverse_encoding((p + 1)/2 + (k - 1) / 2);
                //Finding the new ZpElem corresponing to i in encoging out
                accu[k as usize] = match i{
                    Some(i) => encoding_out.negative_on_p_ring(encoding_out.get_part_single_value_if_canonical(i)),
                    None => 0
                };
            }
        }
        // accu.iter().enumerate().for_each(|(i, x)| print!("{} : {} |", i, x));
        // println!();
        accu
    }



    pub fn create_accumulator_wopbs(encoding_in : &Encoding, encoding_out : &Encoding) -> Accumulator{
        assert!(encoding_in.is_valid());
        assert!(encoding_out.is_canonical());
        let p = encoding_in.get_modulus();
        assert!(p % 2 == 0 && p != 2);
        let mut accu : Accumulator = vec![0;p.try_into().unwrap()];
        for k in 0..p{
             //finding the ZoElem i corresponding to this encoding in
             let i = encoding_in.inverse_encoding(k);
             //Finding the new ZpElem corresponding to i in encoding out
             accu[k as usize] = match i{
                 Some(i) => encoding_out.get_part_single_value_if_canonical(i),
                 None => 0
             };
        }
        // accu.iter().enumerate().for_each(|(i, x)| print!("{} : {} |", i, x));
        // println!();
        accu
    }



    //common part of memory allocation for bootstrappings
    fn allocate_ciphertexts_for_bootstrapping(&mut self, server_key: &ServerKey)->(GlweCiphertext<&mut[u64]>, LweCiphertext<&mut[u64]>, LweCiphertext<&mut[u64]>){
        let num_elem_in_accumulator = server_key.bootstrapping_key.glwe_size().0
            * server_key.bootstrapping_key.polynomial_size().0;
        let num_elem_in_lwe_after_ks = server_key.key_switching_key.output_lwe_size().0;
        let num_elem_in_lwe_after_pbs = server_key
            .bootstrapping_key
            .output_lwe_dimension()
            .to_lwe_size()
            .0;
        let total_elem_needed = num_elem_in_accumulator + num_elem_in_lwe_after_ks + num_elem_in_lwe_after_pbs;

        let all_elements = if self.buffer.len() < total_elem_needed {
            self.buffer.resize(total_elem_needed, 0u64);
            self.buffer.as_mut_slice()
        } else {
            &mut self.buffer[..total_elem_needed]
        };

        let (accumulator_elements, other_elements) =
            all_elements.split_at_mut(num_elem_in_accumulator);

        let accumulator = GlweCiphertext::from_container(
            accumulator_elements,
            server_key.bootstrapping_key.polynomial_size(),
            CiphertextModulus::new_native(),
        );
        let (after_ks_elements, after_pbs_elements) =
        other_elements.split_at_mut(num_elem_in_lwe_after_ks);

        let buffer_lwe_after_ks = LweCiphertextMutView::from_container(
            after_ks_elements,
            CiphertextModulus::new_native(),
        );
        let buffer_lwe_after_pbs = LweCiphertextMutView::from_container(
            after_pbs_elements,
            CiphertextModulus::new_native(),
        );

        (accumulator, buffer_lwe_after_ks, buffer_lwe_after_pbs)
    }




    /// Return a tuple with buffers that matches the server key.
    ///
    /// - The first element is the accumulator for bootstrap step.
    /// - The second element is a lwe buffer where the result of the of the bootstrap should be
    ///   written
    fn as_buffers(
        &mut self,
        server_key: &ServerKey,
        enc_in : &Encoding,
        enc_out : &Encoding
    ) -> BuffersRef<'_>{
        let (mut accumulator, buffer_lwe_after_ks, buffer_lwe_after_pbs) = self.allocate_ciphertexts_for_bootstrapping(server_key);

        ////accumulator filling
        let p = enc_in.get_modulus();
        let new_p = enc_out.get_modulus() as u64;
        accumulator.get_mut_mask().as_mut().fill(0u64);
        let N_poly: usize = accumulator.get_mut_body().as_mut().len();    //(N degree of the polynomial)

        if p != 2{  //wopbs is managed in this block as well

            let accu_data = if p % 2 == 1{
                Self::create_accumulator(enc_in, enc_out)
            }
            else{
                Self::create_accumulator_wopbs(enc_in, enc_out)
            };
            // print!("Accumulator:");
            // accu_data.iter().enumerate().for_each(|(i, x)| print!("{}:{} |", i, x));
            // println!();

            let const_shift = N_poly / (2 * p) as usize;   //half a window

            let mut buffer_value : u64 = ((1 << 64) / new_p as u128) as u64 * accu_data[0] as u64;    //value to be written in the accumulator, put in a u64 to enhance the precision of the / operation
            accumulator.get_mut_body().as_mut()[..const_shift].fill(buffer_value as u64);   //filling of the first half window
            for k in 1..accu_data.len(){
                buffer_value = ((1 << 64) / new_p as u128) as u64 * accu_data[k] as u64;
                accumulator.get_mut_body().as_mut()[const_shift + (k - 1) * N_poly / p as usize..const_shift + k * N_poly / p as usize].fill(buffer_value as u64); //filling of the (k+1)th window
            }
            buffer_value = ((1 << 64) / new_p as u128) as u64 * ((enc_out.get_modulus() - accu_data[0]) % enc_out.get_modulus()) as u64;
            accumulator.get_mut_body().as_mut()[N_poly  - const_shift..].fill(buffer_value as u64);//filling of the last half-window
            // // Debug
            // accumulator.get_body().as_polynomial().iter().for_each(|x| println!("{}", x));
        }
        // for now, the case p=2 is still particular
        else{
            //check that we have negacyclicity
            let new_false = enc_out.get_part_single_value_if_canonical(0);
            let new_true = enc_out.get_part_single_value_if_canonical(1);

            assert!(new_false == (new_p as u64 - new_true) % new_p as u64);
            //Is the 0 window true or false ?
            let (new_0, new_1) = match enc_in.is_partition_containing(1, 0){
                true => (new_true, new_false),
                false => (new_false, new_true)
            };
            //filling of the accu
            let mut buffer_value = ((1 << 64) / new_p as u128) as u64 * new_0 as u64;
            accumulator.get_mut_body().as_mut()[..N_poly / 2].fill(buffer_value as u64);   //filling of the first half window
            buffer_value = ((1 << 64) / new_p as u128) as u64 * new_1 as u64;
            accumulator.get_mut_body().as_mut()[N_poly / 2..].fill(buffer_value as u64);   //filling of the second half window
        }

        BuffersRef {
            lookup_table: accumulator,
            buffer_lwe_after_ks,
            buffer_lwe_after_pbs,
        }
    }




    pub fn as_buffers_common_factor(
        &mut self,
        server_key: &ServerKey,
        enc_out : &Encoding
    ) -> BuffersRef<'_>{
        
        let (mut accumulator, buffer_lwe_after_ks,  buffer_lwe_after_pbs) = self.allocate_ciphertexts_for_bootstrapping(server_key);

        ////accumulator filling
        accumulator.get_mut_mask().as_mut().fill(0u64);

        let constant = if enc_out.get_modulus() % 2 == 0{1u128 << 63} else {1u128 << 64}; 

        accumulator.get_mut_body().as_mut().fill((constant / (enc_out.get_modulus() as u128)) as u64);   //filling the common factor with ones (no taking into account the tau factor here) (il faudra mettre un scaling sinon on va se noyer dans le bruit)


        BuffersRef {
            lookup_table: accumulator,
            buffer_lwe_after_ks,
            buffer_lwe_after_pbs,
        }
    }

}




/// A structure containing the server public key.
///
/// This server key data lives on the CPU.
///
/// The server key is generated by the client and is meant to be published: the client
/// sends it to the server so it can compute homomorphic Boolean circuits.
///
/// In more details, it contains:
/// * `bootstrapping_key` - a public key, used to perform the bootstrapping operation.
/// * `key_switching_key` - a public key, used to perform the key-switching operation.
#[derive(Clone)]
pub struct ServerKey {
    pub(crate) bootstrapping_key: FourierLweBootstrapKeyOwned,
    pub(crate) key_switching_key: LweKeyswitchKeyOwned<u64>,
    pub(crate) lwe_packing_keyswitch_key : LwePackingKeyswitchKeyOwned<u64>,
    pub(crate) pbs_order: PBSOrder
}

impl ServerKey {
    pub fn bootstrapping_key_size_elements(&self) -> usize {
        self.bootstrapping_key.as_view().data().as_ref().len()
    }

    pub fn bootstrapping_key_size_bytes(&self) -> usize {
        std::mem::size_of_val(self.bootstrapping_key.as_view().data())
    }

    pub fn key_switching_key_size_elements(&self) -> usize {
        self.key_switching_key.as_ref().len()
    }

    pub fn key_switching_key_size_bytes(&self) -> usize {
        self.key_switching_key_size_elements() * std::mem::size_of::<u64>()
    }
}


/// Perform ciphertext bootstraps on the CPU
pub(crate) struct Bootstrapper {
    memory: Memory,
    /// A structure containing two CSPRNGs to generate material for encryption like public masks
    /// and secret errors.
    ///
    /// The [`EncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    pub(crate) encryption_generator: EncryptionRandomGenerator<DefaultRandomGenerator>,
    pub(crate) computation_buffers: ComputationBuffers,
    #[allow(dead_code)]
    pub(crate) seeder: DeterministicSeeder<DefaultRandomGenerator>,
}


impl Bootstrapper {
    pub fn new(seeder: &mut dyn Seeder) -> Self {
        Self {
            memory: Memory::default(),
            encryption_generator: EncryptionRandomGenerator::<_>::new(seeder.seed(), seeder),
            computation_buffers: ComputationBuffers::default(),
            seeder: DeterministicSeeder::<_>::new(seeder.seed()),
        }
    }

    pub(crate) fn new_server_key(&mut self, cks: &ClientKey) -> ServerKey {
        let standard_bootstrapping_key: LweBootstrapKeyOwned<u64> =
            par_allocate_and_generate_new_lwe_bootstrap_key(
                &cks.lwe_secret_key,
                &cks.glwe_secret_key,
                cks.parameters.pbs_base_log,
                cks.parameters.pbs_level,
                cks.parameters.glwe_noise_distribution,
                CiphertextModulus::new_native(),
                &mut self.encryption_generator,
            );

        // creation of the bootstrapping key in the Fourier domain
        let mut fourier_bsk = FourierLweBootstrapKey::new(
            standard_bootstrapping_key.input_lwe_dimension(),
            standard_bootstrapping_key.glwe_size(),
            standard_bootstrapping_key.polynomial_size(),
            standard_bootstrapping_key.decomposition_base_log(),
            standard_bootstrapping_key.decomposition_level_count(),
        );

        let fft = Fft::new(standard_bootstrapping_key.polynomial_size());
        let fft = fft.as_view();
        self.computation_buffers.resize(
            convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_requirement(fft)
                .unwrap()
                .unaligned_bytes_required(),
        );

        // Conversion to fourier domain
        par_convert_standard_lwe_bootstrap_key_to_fourier(
            &standard_bootstrapping_key,
            &mut fourier_bsk,
        );

        // Convert the GLWE secret key into an LWE secret key:
        let big_lwe_secret_key = cks.glwe_secret_key.clone().into_lwe_secret_key();

        // creation of the key switching key
        let ksk = allocate_and_generate_new_lwe_keyswitch_key(
            &big_lwe_secret_key,
            &cks.lwe_secret_key,
            cks.parameters.ks_base_log,
            cks.parameters.ks_level,
            cks.parameters.lwe_noise_distribution,
            CiphertextModulus::new_native(),
            &mut self.encryption_generator,
        );

        let packing_ksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
            &big_lwe_secret_key, 
            &cks.glwe_secret_key, 
            cks.parameters.ks_base_log,
            cks.parameters.ks_level,
            cks.parameters.glwe_noise_distribution,
            CiphertextModulus::new_native(),
            &mut self.encryption_generator
        );

        ServerKey {
            bootstrapping_key: fourier_bsk,
            key_switching_key: ksk,
            lwe_packing_keyswitch_key : packing_ksk,
            pbs_order: cks.parameters.encryption_key_choice.into(),
        }
    }





    pub(crate) fn bootstrap(
        &mut self,
        input: &LweCiphertextOwned<u64>,
        accumulator : &GlweCiphertext<Vec<u64>>,
        server_key: &ServerKey) -> LweCiphertextOwned<u64> {
        // let BuffersRef {
        //     lookup_table: accumulator,
        //     mut buffer_lwe_after_pbs,
        //     ..
        // } = self.memory.as_buffers(server_key);

        let mut buffer_lwe_after_pbs = LweCiphertext::new(0u64, server_key
            .bootstrapping_key
            .output_lwe_dimension()
            .to_lwe_size(), CiphertextModulus::new_native());

        let fourier_bsk = &server_key.bootstrapping_key;

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        self.computation_buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
                fourier_bsk.glwe_size(),
                fourier_bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        let stack = self.computation_buffers.stack();


        let mut output_glwe = GlweCiphertext::new(0u64, accumulator.glwe_size(), accumulator.polynomial_size(), accumulator.ciphertext_modulus());

        // programmable_bootstrap_lwe_ciphertext_mem_optimized(
        //     input,
        //     &mut buffer_lwe_after_pbs,
        //     &accumulator,
        //     fourier_bsk,
        //     fft,
        //     stack,
        // );

        programmable_bootstrap_lwe_ciphertext_without_sample_extract_mem_optimized(
            input, 
            &mut output_glwe, 
            &accumulator, 
            fourier_bsk, fft, stack);

        // Self::decrypt_glwe_with_builtin_function(&client_key_debug, &output_glwe);
        
        extract_lwe_sample_from_glwe_ciphertext(&output_glwe, &mut buffer_lwe_after_pbs, MonomialDegree(0));

        LweCiphertext::from_container(
            buffer_lwe_after_pbs.as_ref().to_owned(),
            input.ciphertext_modulus(),
        )
    }


    //perform the BlindRotation of v0
    pub fn bootstrap_common_factor(
        &mut self,
        input: &LweCiphertextOwned<u64>,
        enc_out : &Encoding,
        server_key: &ServerKey
        ) -> GlweCiphertextOwned<u64> {
        let BuffersRef {
            lookup_table:  accumulator,
            ..
        } = self.memory.as_buffers_common_factor(server_key, enc_out);


        let fourier_bsk = &server_key.bootstrapping_key;

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        self.computation_buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
                fourier_bsk.glwe_size(),
                fourier_bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        let stack = self.computation_buffers.stack();


        let mut output = GlweCiphertext::new(0u64, accumulator.glwe_size(), accumulator.polynomial_size(), accumulator.ciphertext_modulus());

        programmable_bootstrap_lwe_ciphertext_without_sample_extract_mem_optimized(
            input,
            &mut output,
            &accumulator,
            fourier_bsk,
            fft,
            stack,
        );


        // Self::decrypt_glwe_with_builtin_function(&client_key_debug, &output);
        // println!("-----------------------");

        GlweCiphertext::from_container(
            output.as_ref().to_owned(),
            output.polynomial_size(),
            input.ciphertext_modulus(),
        )
    }


    fn create_vi_for_mvb(
        &mut self, 
        enc_in : &Encoding,
        enc_out : &Encoding,
        server_key: &ServerKey
    ) -> Polynomial<Vec<u64>>{
        let mut accumulator_data = Memory::create_accumulator(enc_in, enc_out);
        let N_poly: usize = server_key.bootstrapping_key.polynomial_size().0;

   
        let mut accumulator =  Polynomial::new(0u64, PolynomialSize(N_poly));

        let p = enc_in.get_modulus() as usize;
        let mut new_p = enc_out.get_modulus();


        //Here, we perform the division per 2. As for now we use only odd values for p_out, we multiply each accumulator values with the the inverse mod p of 2. Note that if p = 2, other black magic should be performed to get rid of the 2x factor...
        if new_p % 2 == 1{
            let inv2 = (new_p + 1) / 2;
            accumulator_data = accumulator_data.iter().map(|x| x * inv2 % new_p).collect();
        }
        // Else, the division per 2 has been carried out in the v0 rotation.
        else if new_p == 2{
            new_p = 4;
        }
        for i in 0usize..p-1{
            let diff = (accumulator_data[i+1] as i32 - accumulator_data[i] as i32).rem_euclid(new_p as i32) as u64;
            accumulator[N_poly / (2 * p) + i * N_poly / p] = diff;
        }
        let diff = (new_p as i32 - accumulator_data[0] as i32 - accumulator_data[p-1] as i32).rem_euclid(new_p as i32) as u64;
        accumulator[N_poly / (2 * p) + (p-1) * N_poly / p] = diff;

        accumulator
    } 


    // Debug
    // fn decrypt_glwe_with_sample_extraction<OutputCont>(client_key_debug: &ClientKey, glwe_ciphertext : &GlweCiphertext<OutputCont>)
    // where         OutputCont: Container<Element = u64>,
    // {
    //     for i in 0..client_key_debug.parameters.polynomial_size.0{
    //         let lwe_size = LweSize(client_key_debug.parameters.glwe_dimension.0 * client_key_debug.parameters.polynomial_size.0 + 1);
    //         let mut output_lwe = LweCiphertext::new(0u64, lwe_size, CiphertextModulus::new_native());
    //         extract_lwe_sample_from_glwe_ciphertext(&glwe_ciphertext, &mut output_lwe, MonomialDegree(i)); 
    //         println!("{:032b}", decrypt_lwe_ciphertext(&client_key_debug.glwe_secret_key.as_lwe_secret_key(), &output_lwe).0);
    //     }
    // }


    // pub fn decrypt_glwe_with_builtin_function<OutputCont>(client_key_debug : &ClientKey, glwe_ciphertext : &GlweCiphertext<OutputCont>) where
    //     OutputCont: Container<Element = u64>,
    // {
    //     let mut plaintext_list = PlaintextList::new(0u64, PlaintextCount(glwe_ciphertext.polynomial_size().0));
    //     decrypt_glwe_ciphertext(&client_key_debug.glwe_secret_key, &glwe_ciphertext, &mut plaintext_list);
    //     plaintext_list.iter().for_each(|plaintext|println!("{:032b} = {} / {}", plaintext.0, (*plaintext.0 as f64 / (1u64 << 32) as f64 * 5.0).round(), plaintext.0) );
    // }



    pub(crate) fn mvb_bootstrap(
        &mut self,
        ciphertext : LweCiphertextOwned<u64>,
        enc_in : &Encoding,
        encs_out : &Vec<Encoding>,
        lut_fis : &Vec<Vec<u64>>,
        server_key: &ServerKey
    ) -> Vec<LweCiphertext<Vec<u64>>>{
        // let start_mvb = Instant::now();

        // let start_bootstrapping_common_factor = Instant::now();
        // Ici problème si les outputs n'ont pas tout le même modulo d'encodage

        let v0 = self.bootstrap_common_factor(&ciphertext, &encs_out[0], server_key);

        // Self::decrypt_glwe_with_builtin_function(&client_key_debug, &v0);
        // println!("----------------------------------------");
        // let stop_bootstrapping_common_factor = start_bootstrapping_common_factor.elapsed();
        // println!("Durée BR common factor: {:?}: {:?}", stop_bootstrapping_common_factor.as_millis(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap());

        // construction of the vi's:
        let vis : Vec<Polynomial<_>> = encs_out.iter().zip(lut_fis)
                        .map(|(enc_out, lut_fi)| (enc_out, |x| lut_fi[x as usize]) )
                        .map(|(enc_out, fi)| (enc_in.apply_lut_to_encoding(&fi), enc_out))
                        .map(|(enc_inter, enc_out)| {self.create_vi_for_mvb(&enc_inter, enc_out, server_key)})
                        .collect();

        // vis[0].iter().for_each(|x| println!("{}|", x));


        // let start_polynomial_multiplications = Instant::now();
        //Multiplication between accumulators and the vi's
        let mut result = vec![];
        for vi in vis{
            let mut accu_i = GlweCiphertext::new(0u64, v0.glwe_size(), v0.polynomial_size(), v0.ciphertext_modulus());
            accu_i.as_mut_polynomial_list().iter_mut().zip(v0.as_polynomial_list().iter()).for_each(|(mut output, v0_poly_j)| polynomial_karatsuba_wrapping_mul(&mut output, &v0_poly_j, &vi));

            //Sample Extraction
            let mut output_lwe_i = LweCiphertext::new(0u64, accu_i.glwe_size().to_glwe_dimension().to_equivalent_lwe_dimension(accu_i.polynomial_size()).to_lwe_size(), accu_i.ciphertext_modulus());
            extract_lwe_sample_from_glwe_ciphertext(&accu_i, &mut output_lwe_i, MonomialDegree(0));
            result.push(output_lwe_i)
        }
        // let stop_polynomial_multiplications = start_polynomial_multiplications.elapsed();
        // println!("Durée Polynomial multiplication: {:?}: {:?}", stop_polynomial_multiplications.as_millis(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap());

        // let stop_mvb = start_mvb.elapsed();
        // println!("Durée MVB: {:?}: {:?}", stop_mvb.as_millis(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap());
        result

    }



    pub fn _decrypt_glwe_with_builtin_function<OutputCont>(client_key_debug : &ClientKey, glwe_ciphertext : &GlweCiphertext<OutputCont>) where
    OutputCont: Container<Element = u64>,
        {
            let mut plaintext_list = PlaintextList::new(0u64, PlaintextCount(glwe_ciphertext.polynomial_size().0));
            decrypt_glwe_ciphertext(&client_key_debug.glwe_secret_key, &glwe_ciphertext, &mut plaintext_list);
            plaintext_list.iter().for_each(|plaintext|println!("{:032b} = {} / {}", plaintext.0, (*plaintext.0 as f64 / (1u64 << 32) as f64 * 5.0).round(), plaintext.0) );
        }



    pub(crate) fn mvb_bootstrap_with_common_factor_given(
        &mut self,
        common_factor : &GlweCiphertext<Vec<u64>>,
        enc_in : &Encoding,
        encs_out : &Vec<Encoding>,
        lut_fis : &Vec<Vec<u64>>,
        server_key: &ServerKey,
        client_key_debug : &ClientKey
    ) -> Vec<LweCiphertext<Vec<u64>>>{
        // let start_mvb = Instant::now();

        // let start_bootstrapping_common_factor = Instant::now();
        // Ici problème si les outputs n'ont pas tout le même modulo d'encodage

        let v0: &GlweCiphertext<Vec<u64>> = common_factor;

        // Self::decrypt_glwe_with_builtin_function(&client_key_debug, &v0_bis);
        // println!("----------------------------------------");
        // let stop_bootstrapping_common_factor = start_bootstrapping_common_factor.elapsed();
        // println!("Durée BR common factor: {:?}: {:?}", stop_bootstrapping_common_factor.as_millis(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap());

        // construction of the vi's:
        let vis : Vec<Polynomial<_>> = encs_out.iter().zip(lut_fis)
                        .map(|(enc_out, lut_fi)| (enc_out, |x| lut_fi[x as usize]) )
                        .map(|(enc_out, fi)| (enc_in.apply_lut_to_encoding(&fi), enc_out))
                        .map(|(enc_inter, enc_out)| {self.create_vi_for_mvb(&enc_inter, enc_out, server_key)})
                        .collect();

        // vis[0].iter().for_each(|x| println!("{}|", x));


        // let start_polynomial_multiplications = Instant::now();
        //Multiplication between accumulators and the vi's
        let mut result = vec![];
        for vi in vis{
            let mut accu_i = GlweCiphertext::new(0u64, v0.glwe_size(), v0.polynomial_size(), v0.ciphertext_modulus());
            accu_i.as_mut_polynomial_list().iter_mut().zip(v0.as_polynomial_list().iter()).for_each(|(mut output, v0_poly_j)| polynomial_karatsuba_wrapping_mul(&mut output, &v0_poly_j, &vi));
            
            // Self::decrypt_glwe_with_builtin_function(&client_key_debug, &accu_i);
            // println!("------------------------------------------");

            //Sample Extraction
            let mut output_lwe_i = LweCiphertext::new(0u64, accu_i.glwe_size().to_glwe_dimension().to_equivalent_lwe_dimension(accu_i.polynomial_size()).to_lwe_size(), accu_i.ciphertext_modulus());
            extract_lwe_sample_from_glwe_ciphertext(&accu_i, &mut output_lwe_i, MonomialDegree(0));
            result.push(output_lwe_i)
        }
        // let stop_polynomial_multiplications = start_polynomial_multiplications.elapsed();
        // println!("Durée Polynomial multiplication: {:?}: {:?}", stop_polynomial_multiplications.as_millis(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap());

        // let stop_mvb = start_mvb.elapsed();
        // println!("Durée MVB: {:?}: {:?}", stop_mvb.as_millis(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap());
        result

    }


    pub(crate) fn pack_into_new_accumulator(
        &self, 
        lwe_ciphertexts : Vec<LweCiphertextOwned<u64>>,
        server_key : &ServerKey,
        p : u64,
    ) -> GlweCiphertext<Vec<u64>>{
        let mut output_glwe_ciphertext = GlweCiphertext::new(0u64, server_key.bootstrapping_key.glwe_size(), server_key.bootstrapping_key.polynomial_size(), CiphertextModulus::new_native());

        //reordering accumulator
        let accumulator_elements : Vec<_> = (0..p).map(|k|{
            if k % 2 == 0{ 
                match lwe_ciphertexts.get(k as usize/2){
                    Some(c) => c.clone(),
                    None => LweCiphertext::new(0u64, lwe_ciphertexts[0].lwe_size(), CiphertextModulus::new_native())
            }}
            else{
                match lwe_ciphertexts.get(((p+1)/2 + (k-1)/2) as usize){
                    Some(c) => {
                        let mut c_clone = c.clone();
                        lwe_ciphertext_opposite_assign(&mut c_clone);
                        c_clone
                    },
                    None => LweCiphertext::new(0u64, lwe_ciphertexts[0].lwe_size(), CiphertextModulus::new_native())
                }
            }
        }).collect();


        assert!(p % 2 == 1, "Pas sûr que ça marche avec une output paire");
        let N = server_key.bootstrapping_key.polynomial_size().0;
        let size_slice = N / p as usize;



        if p % 2 == 1{

            let mut buffer = GlweCiphertext::new(
                0u64,
                output_glwe_ciphertext.glwe_size(),
                output_glwe_ciphertext.polynomial_size(),
                output_glwe_ciphertext.ciphertext_modulus(),
            );



            //index \in [0, p-2]
            for (k, elmt) in accumulator_elements.iter().enumerate(){
                keyswitch_lwe_ciphertext_into_glwe_ciphertext(&server_key.lwe_packing_keyswitch_key, &elmt, &mut buffer);
                
                let number_of_repetition = if k == 0 {size_slice/2} else {size_slice};
                (0..number_of_repetition).for_each(|i|{
                    let mut buffer_bis = buffer.clone();
                    buffer_bis.
                        as_mut_polynomial_list()
                        .iter_mut()
                        .for_each(|mut poly| {
                            let offset = if k == 0 {0} else {size_slice / 2 + (k - 1) * size_slice};
                            polynomial_wrapping_monic_monomial_mul_assign(&mut poly, MonomialDegree(offset  + i));
                        });
                    slice_wrapping_add_assign(output_glwe_ciphertext.as_mut(), buffer_bis.as_ref());
                });
            }

            // index = p-1 (last one)
            keyswitch_lwe_ciphertext_into_glwe_ciphertext(&server_key.lwe_packing_keyswitch_key, &accumulator_elements[0], &mut buffer);
                glwe_ciphertext_opposite_assign(&mut buffer);
                (0..size_slice/2).for_each(|i|{
                    let mut buffer_bis = buffer.clone();
                    buffer_bis.
                        as_mut_polynomial_list()
                        .iter_mut()
                        .for_each(|mut poly| {
                            polynomial_wrapping_monic_monomial_mul_assign(&mut poly, MonomialDegree(N - size_slice / 2 + i));
                        });
                    slice_wrapping_add_assign(output_glwe_ciphertext.as_mut(), buffer_bis.as_ref());
                })
    

        }

        output_glwe_ciphertext


    }


    pub(crate) fn bootstrap_keyswitch(
        &mut self,
        mut ciphertext: LweCiphertextOwned<u64>,
        enc_inter : &Encoding,
        enc_out : &Encoding,
        server_key: &ServerKey,
    ) -> Ciphertext{
        let BuffersRef {
            lookup_table: accumulator,
            mut buffer_lwe_after_pbs,
            ..
        } = self.memory.as_buffers(server_key, enc_inter, enc_out);

        let fourier_bsk = &server_key.bootstrapping_key;

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        self.computation_buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
                fourier_bsk.glwe_size(),
                fourier_bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        let stack = self.computation_buffers.stack();

        // Compute a bootstrap
        programmable_bootstrap_lwe_ciphertext_mem_optimized(
            &ciphertext,
            &mut buffer_lwe_after_pbs,
            &accumulator,
            fourier_bsk,
            fft,
            stack,
        );

        // Compute a key switch to get back to input key
        keyswitch_lwe_ciphertext(
            &server_key.key_switching_key,
            &buffer_lwe_after_pbs,
            &mut ciphertext,
        );

        Ciphertext::EncodingEncrypted(ciphertext, enc_out.clone())
    }




    pub(crate) fn keyswitch_bootstrap(
            &mut self,
            mut ciphertext: LweCiphertextOwned<u64>,
            enc_inter : &Encoding,
            enc_out : &Encoding,
            server_key: &ServerKey,
    ) -> Ciphertext {
        let BuffersRef {
            lookup_table,
            mut buffer_lwe_after_ks,
            ..
        } = self.memory.as_buffers(server_key, enc_inter, enc_out);

        let fourier_bsk = &server_key.bootstrapping_key;

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        self.computation_buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
                fourier_bsk.glwe_size(),
                fourier_bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        let stack = self.computation_buffers.stack();

        // let start_keyswitch = Instant::now();
        // Keyswitch from large LWE key to the small one
        keyswitch_lwe_ciphertext(
            &server_key.key_switching_key,
            &ciphertext,
            &mut buffer_lwe_after_ks,
        );
        // let stop_keyswitch = start_keyswitch.elapsed();
        // println!("Durée Keyswitch: {:?}: {:?}", stop_keyswitch.as_millis(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap());


        // let start_bootstrap = Instant::now();
        // Compute a bootstrap
        programmable_bootstrap_lwe_ciphertext_mem_optimized(
            &buffer_lwe_after_ks,
            &mut ciphertext,
            &lookup_table,
            fourier_bsk,
            fft,
            stack
        );
        // let stop_bootstrap = start_bootstrap.elapsed();
        // println!("Durée Bootstrap: {:?}: {:?}", stop_bootstrap.as_millis(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap());

        Ciphertext::EncodingEncrypted(ciphertext, enc_out.clone())
    }

    
    pub(crate) fn apply_bootstrapping_pattern(
        &mut self,
        ct: LweCiphertextOwned<u64>,
        enc_inter : &Encoding,
        enc_out : &Encoding,
        server_key: &ServerKey,
    ) -> Ciphertext {
        match server_key.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.keyswitch_bootstrap(ct, enc_inter, enc_out, server_key),
            PBSOrder::BootstrapKeyswitch => self.bootstrap_keyswitch(ct, enc_inter, enc_out, server_key),
        }
    }
}


impl ServerKey {
    pub(crate) fn keyswitch(&self, input: &LweCiphertextOwned<u64>) -> LweCiphertextOwned<u64> {
        // Allocate the output of the KS
        let mut output = LweCiphertext::new(
            0u64,
            self.bootstrapping_key.input_lwe_dimension().to_lwe_size(),
            input.ciphertext_modulus(),
        );

        keyswitch_lwe_ciphertext(&self.key_switching_key, input, &mut output);

        output
    }
}
