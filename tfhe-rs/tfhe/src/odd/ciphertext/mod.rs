//! An encryption of a boolean message.
//!
//! This module implements the ciphertext structure containing an encryption of a Boolean message.

use crate::core_crypto::entities::*;
use std::collections::{HashMap, HashSet};


#[derive(Clone, Debug)]
pub enum Ciphertext {
    EncodingEncrypted(LweCiphertextOwned<u64>, Encoding),
    Trivial(ZpElem),
}

type ZoElem = u64;
type ZpElem = u64;

#[derive(Clone, Debug)]
pub struct Encoding {
    origin_modulus: u64,         // o in the paper
    parts: Vec<HashSet<ZpElem>>, //element of index i \in \Zo returns the elems of \Zp associated with i in the encoding.
    modulus_p: u64,              //p in the paper
}

impl PartialEq for Encoding {
    fn eq(&self, other: &Self) -> bool {
        self.get_origin_modulus() == other.get_origin_modulus()
            && self.get_modulus() == other.get_modulus()
            && self
                .parts
                .iter()
                .zip(other.parts.clone())
                .all(|(set1, set2)| *set1 == set2)
    }
}

impl Encoding {
    pub fn is_valid(&self) -> bool {
        assert_eq!(self.origin_modulus, self.parts.len().try_into().unwrap());

        let x = self.parts.iter().enumerate().all(|(i, part_1)| {
            self.parts
                .iter()
                .skip(i + 1)
                .all(|part_2| part_1.is_disjoint(part_2))
        }); //check disjonction of all parts
        let x = true;

        let y = match self.modulus_p % 2 == 1 || self.modulus_p == 2 {
            true => true,
            false => {
                //check negacyclicity : if a ZpElem belongs to the ith parts, its opposite on Zp should not belong to any part except the [-i]_o one.
                for i in (0..self.origin_modulus).map(|i| i as ZoElem) {
                    let negative_i = self.negative_on_o_ring(i);
                    for x in self.get_part(i).iter().map(|x| *x as ZpElem) {
                        let opposite_x = (x + self.modulus_p / 2) % self.modulus_p;
                        let forbidden_spots = self
                            .parts
                            .iter()
                            .enumerate()
                            .filter(|(j, _)| *j as ZoElem != negative_i)
                            .map(|(_, part)| part)
                            .fold(HashSet::new(), |acc, set| acc.union(set).cloned().collect());
                        if forbidden_spots.contains(&opposite_x) {
                            return false;
                        }
                    }
                }
                true
            }
        };
        x & y
    }

    pub fn pretty_print(&self) {
        println!("modulus : {}", self.modulus_p);
        self.parts.iter().enumerate().for_each(|(i, part)| {
            print!("{} : {{", i);
            part.iter().for_each(|x| print!("{}, ", x));
            println!("}}");
        })
    }

    pub fn is_partition_containing(&self, element_of_zo: u64, value: u64) -> bool {
        //est-ce que la partition associée à l'élément contient la valeur ?
        self.get_part(element_of_zo).contains(&value)
    }

    pub fn inverse_encoding(&self, x: ZpElem) -> Option<ZoElem> {
        //returns the value in Zo encoded by the ZpElem x
        for i in 0..self.origin_modulus {
            if self.is_partition_containing(i, x) {
                return Some(i);
            }
        }
        return None; //placeholder, this ZpElem is never reached
    }

    pub fn is_canonical(&self) -> bool {
        self.parts.iter().all(|part| part.len() == 1)
    }

    pub fn get_modulus(&self) -> u64 {
        self.modulus_p
    }

    pub fn negative_on_p_ring(&self, x: ZpElem) -> ZpElem {
        // for x, return [p - x] % p. Do not mix up with opposite, a.k.a. x + p / 2 !
        (self.modulus_p - x) % self.modulus_p
    }

    pub fn add_constant(&self, constant: ZpElem) -> Self {
        Self::new(
            self.origin_modulus,
            self.parts
                .iter()
                .map(|part| {
                    part.iter()
                        .map(|x| (x + constant) % self.get_modulus())
                        .collect()
                })
                .collect(),
            self.get_modulus(),
        )
    }
}

impl Encoding {
    pub fn get_origin_modulus(&self) -> u64 {
        self.origin_modulus
    }

    pub fn get_part(&self, element_of_zo: ZoElem) -> &HashSet<u64> {
        &self.parts[element_of_zo as usize]
    }

    pub fn get_part_single_value_if_canonical(&self, element_of_zo: ZoElem) -> ZpElem {
        assert!(self.is_canonical());
        self.get_part(element_of_zo)
            .iter()
            .next()
            .unwrap()
            .to_owned()
    }

    pub fn negative_on_o_ring(&self, element_of_zo: ZoElem) -> ZoElem {
        (self.origin_modulus - element_of_zo) % self.origin_modulus
    }

    pub fn new(origin_modulus: u64, parts: Vec<HashSet<ZpElem>>, modulus_p: u64) -> Self {
        assert!(parts.iter().all(|part| part.iter().all(|x| *x < modulus_p)));
        let new_encoding = Self {
            origin_modulus,
            parts,
            modulus_p,
        };
        if new_encoding.is_valid() {
            new_encoding
        } else {
            panic!("This Arithmetic Encoding is not correct !");
        }
    }

    pub fn new_canonical(
        origin_modulus: u64,
        values_for_singletons: Vec<ZpElem>,
        modulus_p: u64,
    ) -> Self {
        Self::new(
            origin_modulus,
            values_for_singletons
                .iter()
                .map(|d| HashSet::from([*d]))
                .collect(),
            modulus_p,
        )
    }

    pub fn new_canonical_binary(value_for_singleton_true: ZpElem, modulus_p: u64) -> Self {
        Self::new_canonical(2, vec![0, value_for_singleton_true], modulus_p)
    }

    pub fn parity_encoding() -> Self {
        Self::new_canonical_binary(1, 2)
    }

    pub fn new_trivial(origin_modulus: u64) -> Self {
        Self::new_canonical(
            origin_modulus,
            (0..origin_modulus).collect(),
            origin_modulus,
        )
    }


    pub fn apply_lut_to_encoding(&self, f: &dyn Fn(ZoElem) -> ZoElem) -> Self {
        //the origin modulus of the ouput may be different as the one of the input.
        let mut parts_hashmap: HashMap<ZoElem, HashSet<ZpElem>> = HashMap::new();
        for i in 0..self.origin_modulus {
            match parts_hashmap.get_mut(&f(i)) {
                Some(part) => self.get_part(i).iter().for_each(|x: &ZpElem| {
                    part.insert(*x);
                }),
                None => {
                    parts_hashmap.insert(f(i), self.get_part(i).to_owned());
                }
            };
        }
        let parts = (0..self.origin_modulus)
            .map(|i| match parts_hashmap.get(&i) {
                Some(part) => part.to_owned(),
                None => HashSet::new(),
            })
            .collect();
        Self::new(self.origin_modulus, parts, self.modulus_p)
    }

    pub fn multiply_encoding_by_constant(&self, constant: ZpElem) -> Self {
        Self::new(
            self.origin_modulus,
            self.parts
                .iter()
                .map(|x| {
                    x.iter()
                        .map(|xi| *xi * constant % self.get_modulus())
                        .collect()
                })
                .collect(),
            self.get_modulus(),
        )
    }
}


// #[test]
// fn test_boolean_encoding(){
//     let e = BooleanEncoding::new_canonical(2, 7);
//     assert!(e.is_valid());
//     let e = BooleanEncoding::new_canonical(1, 2);
//     assert!(e.is_valid());
// }

// #[test]
// #[should_panic]
// fn bad_boolean_encoding_even_p(){
//     let e = BooleanEncoding::new([0, 2].into(), [1].into(), 4);
// }

// #[test]
// #[should_panic]
// fn bad_boolean_encoding_duplicate_i(){
//     let e = BooleanEncoding::new([0, 2].into(), [0].into(), 5);
// }

#[test]
#[should_panic]
fn bad_arithmetic_encoding_duplicate_i() {
    let _: Encoding = Encoding::new(3, [[0, 2].into(), [0].into(), [1].into()].into(), 5);
}

#[test]
#[should_panic]
fn bad_arithmetic_encoding_negacyclicity() {
    let _ = Encoding::new_canonical(3, vec![1, 5, 2], 8);
}

#[test]
fn good_arithmetic_encoding_negacyclicity() {
    let _ = Encoding::new_canonical(3, vec![2, 1, 5], 8);
}
