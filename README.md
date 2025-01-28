This repository contains the companion code of the Hippogryph paper, that can be found at:

https://eprint.iacr.org/2025/075.pdf


The code of Hippogryph itself can be found in the `hippogryph` folder.


The folder `tfhe-rs` contains the implementation of the tfhe scheme, originally taken from 

https://github.com/zama-ai/tfhe-rs

As Hippogryph requires som new cryptographic primitives not implemented in the original `tfhe-rs`, we added a feature `odd` that can be found in `tfhe-rs/tfhe/src/odd`. The main contributions are:

- The modification of the tfhe scheme to support odd modulis
- The $(o, p)$-encoding notion
- The advanced homomorphic operators "multi-value bootstrapping" and "tree bootstrapping"


If any questions, contact the authors of the papers.
