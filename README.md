# Hippogryph, a Fast Homomorphic Implementation of AES using TFHE

This repository contains the code of **Hippogryph**. Its design has been presented in a paper that can be found at:

https://eprint.iacr.org/2025/075.pdf



# Structure of the repository


The code of Hippogryph itself can be found in the `hippogryph` folder.


The folder `tfhe-rs` contains the implementation of the TFHE scheme. As Hippogryph requires some new cryptographic primitives not implemented in the original `tfhe-rs`, we added a feature `odd` that can be found in `tfhe-rs/tfhe/src/odd`. The main contributions are:

- The modification of the tfhe scheme to support odd moduli
- The $(o, p)$-encoding notion
- The advanced homomorphic operators "multi-value bootstrapping" and "tree bootstrapping"

Example of usage:


```
./target/release/hippogriph --number-of-outputs 100 --iv "00112233445566778899AABBCCDDEEFF" --key "000102030405060708090A0B0C0D0E0F
```

It will run the clear evaluation of AES, then the encrypted one and compare them.

# For more documentation

A pdf document is provided with this submission. It synthetizes the content of our paper.