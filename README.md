This repository contains the companion code of the Hippogriph paper, that can be found in:

https://eprint.iacr.org/2025/075.pdf


The code of Hippogriph itself can be found in the `hippogriph` folder.


The folder `the-rs` contains the implementation if the tfhe-scheme, originally taken from 

https://github.com/zama-ai/tfhe-rs

As hippogriph requires som new cryptographic primitives not implemented in the original `tfhe-rs`, we added a feature `odd` that can be found in `tfhe-rs/tfhe/src/odd`. The main contributions are:

- The modification of the tfhe scheme to support odd modulis
- The $(o-p)$ encoding notion
- The advanced homomorphic operators "multi-value bootstrapping" and "tree bootstrapping"


If any questions, contact the authors of the papers.
