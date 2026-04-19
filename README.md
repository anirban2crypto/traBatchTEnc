# Traceable Threshold Batch Encryption

### Implementation of the paper appearing at [ACM ASIA CCS 2026](https://asiaccs2026.org)

> **Traceable Threshold Batch Encryption with Applications to Enhancing Mempool Privacy**

---

## 📖 Overview

This repository is the reference implementation accompanying the above paper.

We introduce **Traceable Batched Threshold Encryption (T-BTE)**, a new cryptographic primitive designed to strengthen the privacy and accountability of blockchain mempools. T-BTE extends Batched Threshold Encryption (BTE) — where decryption requires a quorum of *t* validators — with **traceability**: the ability to identify malicious validators who leak or misuse their decryption shares.

Key contributions:

- **First formal definitions and construction for T-BTE**, achieving CCA security.
- **Bipartite Batched Threshold Encryption (Bi-BTE)** — a new primitive built from bilinear pairings and a one-time signature, proved secure in the Generic Group Model (GGM).
- **T-BTE construction** combining Bi-BTE with a fingerprinting code (Boneh et al., DRM 2010).
- **First known implementation of a fingerprinting code**, together with a full Rust implementation of Bi-BTE, demonstrating practical efficiency for encrypted mempools.



## 📊 Benchmarking

Run the full benchmark suite with:

```bash
bash runscript.sh    # end-to-end performance (key gen, encryption, decryption)
bash runtrace.sh     # tracing performance
```

Each script logs timestamped output to a file and prints a machine-info header automatically.

### 🖥️ Reference machine

| Field   | Value |
|---------|-------|
| CPU     | Intel Core i5-7200U @ 2.50 GHz (Turbo 3.10 GHz) |
| Cores   | 2 physical / 4 logical (Hyper-Threading) |
| RAM     | 7.6 GiB |
| OS      | Linux 6.17 x86\_64 |
| Rust    | rustc 1.94.1 |

### ⏱️ Sample end-to-end timings (B=128, n=8, code\_constant=30, coalition=4)

```
╔═════════════════════════════════════════════════════════════╗
║      Traceable Batch Threshold Encryption — End-to-End      ║
╠═════════════════════════════════════════════════════════════╣
║  Batch size :  128    Users (n) :   8    Code constant :  30 ║
║  Coalition  :    4    Total keys :    480                    ║
╚═════════════════════════════════════════════════════════════╝

··End:     Key Generation ..........................................2.580s
··End:     Encryption ..............................................2.850s
··End:     Partial Decryptions ....................................14.833ms
··End:     Combine ................................................497.483µs
··End:     Decryption ..............................................1.019s

┌─────────────────────────────────────────────────────────────┐
│                    Communication Costs                      │
├──────────────────────────────────────┬──────────────────────┤
│   Secret key  (480 keys)             │              292 KB  │
│   Public key + CRS                   │              153 KB  │
│   Ciphertext  (per batch)            │              544 B   │
│   Partial decryption (per user)      │               57 B   │
│   Sigma  (aggregated)                │               96 B   │
└──────────────────────────────────────┴──────────────────────┘
```

> Timings are single-threaded. Performance scales with CPU clock speed and available memory bandwidth.

---

## 🐞 Debugging & Testing

Use the following commands to test and debug different components of the implementation:


```bash
# Run end-to-end example with full output
cargo run --example endtoend -- --nocapture

# Test Key Generation
cargo test --features KeyTest -- --nocapture

# Test CRS Generation
cargo test --features CRSTest -- --nocapture

# Test Encryption
cargo test --features EncTest -- --nocapture

# Test Fingerprinting Code
cargo test --features CodeTest -- --nocapture

# Test Decoder
cargo test --features DecoderTest -- --nocapture

# Test Tracing
cargo test --features TraceTest -- --nocapture
```

## ⚠️ Disclaimer

Please note that this code has **not been cleaned for compiler warnings**. Compilation may produce warnings that have not been addressed.

**WARNING:** This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.

## Dependencies
* [arkworks](http://arkworks.rs) project for finite field and elliptic curve arithmetic.
* [merlin](https://github.com/dalek-cryptography/merlin) library for implementing the Fiat-Shamir transform.

### 📄 Declaration

This version includes improvements and new features built on top of the original batched-threshold encryption scheme [guruvamsi-policharla/batched-threshold-pp](https://github.com/guruvamsi-policharla/batched-threshold-pp) an improved batched-threshold encryption scheme as described in [ePrint:2024/151].

The copyright notice has been retained from the original work.