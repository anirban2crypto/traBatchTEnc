# Batched Threshold Encryption++

### 📄 Declaration

This version includes improvements and new features built on top of the original batched-threshold encryption scheme [guruvamsi-policharla/batched-threshold-pp](https://githubs an improved batched-threshold encryption scheme as described in [ePrint:2024/151.

The copyright notice has been retained from the original work.

Adapted from: Rust implementation https://github.com/guruvamsi-policharla/batched-threshold-pp the improved batched-threshold encryption scheme introduced in [ePrint:2024/1516](https://eprint.iacr.org/2024/1516).

**The copyright notice is included from prior work.** 


## 📊 Benchmarking

You can use the following scripts to run benchmarks:

- `runscript.sh` – Main benchmarking script  
- `runtrace.sh` – Benchmarking for trace functionality

---

## 🐞 Debugging & Testing

Use the following commands to test and debug different components of the implementation:


### Run end-to-end example with full output
cargo run --example endtoend -- --nocapture

### Test Key Generation
cargo test --features KeyTest -- --nocapture

### Test CRS Generation
cargo test --features CRSTest -- --nocapture

### Test Encryption
cargo test --features EncTest -- --nocapture

### Test Fingerprinting Code
cargo test --features CodeTest -- --nocapture

### Test Decoder
cargo test --features DecoderTest -- --nocapture

### Test Tracing
cargo test --features TraceTest -- --nocapture

## ⚠️ Disclaimer

Please note that this code has **not been cleaned for compiler warnings**. Compilation may produce warnings that have not been addressed.

**WARNING:** This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.

## Dependencies
* [arkworks](http://arkworks.rs) project for finite field and elliptic curve arithmetic.
* [merlin](https://github.com/dalek-cryptography/merlin) library for implementing the Fiat-Shamir transform.

