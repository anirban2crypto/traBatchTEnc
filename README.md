# Batched Threshold Encryption++


Adapted from: Rust implementation https://github.com/guruvamsi-policharla/batched-threshold-pp the improved batched-threshold encryption scheme introduced in [ePrint:2024/1516](https://eprint.iacr.org/2024/1516).

**copyright notice also inherited from previous work** 


#Benchmarking

runscript.sh
runtrace.sh


#Debuging 

Use ```cargo run --example endtoend -- --nocapture``` to check correctness of the implementation.

Use ```cargo test --features KeyTest -- --nocapture``` to check correctness of the keygen

Use ```cargo test --features CRSTest -- --nocapture``` to check correctness of the crsgen

Use ```cargo test --features EncTest -- --nocapture``` to check correctness of the enc

Use ```cargo test --features CodeTest -- --nocapture``` to check correctness of the fingerprinting code

Use ```cargo test --features DecoderTest -- --nocapture``` to check correctness of the decoder

Use ```cargo test --features TraceTest -- --nocapture``` to check correctness of the Trace



**WARNING:** This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.

## Dependencies
* [arkworks](http://arkworks.rs) project for finite field and elliptic curve arithmetic.
* [merlin](https://github.com/dalek-cryptography/merlin) library for implementing the Fiat-Shamir transform.

