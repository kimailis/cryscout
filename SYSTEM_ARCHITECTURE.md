# CryScout System Architecture

## 1. Overview
CryScout is a high-performance, distributed cryptanalytic suite designed to identify and exploit vulnerabilities in Bitcoin ECDSA signatures. Originally developed in Python, the system has transitioned to a multi-crate Rust architecture for maximum performance, concurrency, and reliability.

## 2. Subsystems & Components

### 2.1 Core Infrastructure
- **`cryshub_rs` (The Hub)**: The central orchestration service. It manages the lifecycle of all worker processes, monitors system health (CPU/RAM), handles inter-process communication via signals (`SIGNAL_FILE`), and logs system-wide events.
- **`crypdash_rs` (The Dashboard)**: A terminal-based UI (built with Ratatui) that provides real-time visualization of the entire fleet. It displays global statistics, active workers, potential targets, and recovered keys.
- **SQLite Database (`cryscout.db`)**: The central state repository. It stores tracked addresses, extracted signatures, vulnerability findings, worker heartbeats, and recovered private keys.

### 2.2 Workers & Analyzers
- **`cryscout_worker_rs`**: A versatile worker that can operate in four modes:
    - **Scanner**: Monitors the target queue and triggers replenishment from external APIs (like mempool.space) when targets are exhausted.
    - **Analyzer**: Performs initial statistical passes on collected signatures.
    - **Scorer**: Implements a complex multi-factor ranking system (see Section 4).
    - **Striker**: The high-priority attack orchestrator that executes intensive cryptographic attacks on high-probability targets.
- **`address_analyzer_rs`**: Specialized signature fetcher. It performs deep transaction parsing and reconstructs the message hash (`z-value`) for Legacy (P2PKH) and SegWit (v0) transactions, essential for ECDSA key recovery.
- **`wallet_scout_rs`**: A high-speed BIP39 mnemonic brute-forcer that generates millions of wallet combinations per second and checks them against the target database.

### 2.3 Cryptographic Attack Modules
- **`lattice_attack_rs`**: Implements the Hidden Number Problem (HNP) solver using LLL (Lenstra–Lenstra–Lovász) and BKZ (Block Korkine-Zolotarev) lattice reduction algorithms. It recovers private keys from nonces with as few as 2-4 biased bits.
- **`nonce_relation_rs`**: A suite of algebraic attacks:
    - **Point-based Delta Scan**: Finds $k_i = k_j + \delta$ relationships.
    - **Polynonce Attack**: Exploits linear and quadratic polynomial relationships in nonce generation.
    - **Ratio Attack**: Detects $a \cdot k_i = b \cdot k_j$ patterns.
- **`kangaroo_rs`**: Implementation of Pollard's Kangaroo algorithm for solving the Discrete Logarithm Problem (DLP) within a bounded range, used when partial key information is recovered via lattice or other methods.
- **`bias_detector_rs`**: Performs Spectral (FFT) and Neural (ONNX) analysis to identify non-randomness in nonce distributions.
- **`bleichenbacher_fourier` & `fourier_attack`**: Advanced Fourier-based solvers for detecting and exploiting subtle periodicities in nonces across large signature datasets (100+ sigs).

---

## 3. Schema of Operation

1.  **Discovery**: The **Scanner** identifies high-value dormant or active addresses via blockchain "rich lists" and API monitoring.
2.  **Collection**: **`address_analyzer_rs`** extracts all available (r, s, z) tuples for an address.
3.  **Vulnerability Scoring**: The **Scorer** runs a suite of tests (LSB/MSB bias, entropy, FFT, correlation) and assigns a `vulnerability_score`.
4.  **Targeting**: Addresses are ranked in the database; those with high scores are flagged for the **Striker**.
5.  **Execution**: The **Striker** launches a sequence of attacks:
    - **Collision Check**: Immediate recovery if the same nonce was used for different messages.
    - **Relation Scan**: Algebraic check for deterministic nonce bugs.
    - **Lattice Strike**: LLL/BKZ reduction for biased nonces.
    - **Neural/Fourier Check**: Final verification of complex patterns.
6.  **Recovery**: If a private key is found, it is verified against the target address hash and saved to the `recovered_keys` table.

---

## 4. Address Lifecycle

1.  **Tracked**: Address is added to the database (from rich lists or manual input).
2.  **Sigs Fetched**: Transaction history is parsed, and signatures are stored.
3.  **Analyzed/Scored**: Statistical and neural metrics are calculated.
4.  **Vulnerable**: Address shows significant bias (e.g., LSB bias, Spectral peak).
5.  **Processing**: A **Striker** worker has claimed the address for intensive computation.
6.  **Scanned**: All primary attack vectors have been exhausted without success.
7.  **Recovered**: The private key has been successfully derived.

---

## 5. Neural Network Integration

### 5.1 Models
- **`nonce_anomaly_model.onnx` (FFNN)**: A Feed-Forward Binary Classifier that predicts the probability ($P$) that a set of nonces is "vulnerable" vs. "properly random."
- **`spectral_bias_lstm.onnx` (LSTM)**: A sequence model that detects periodicity and predictability in the bit-patterns of nonces over time.

### 5.2 Feature Extraction (438 Dimensions)
The system extracts 438 features from a set of nonces, including:
- **Bit Distribution (256)**: Frequency of each bit position being set across the signature set.
- **Byte Entropy (32)**: Shannon entropy calculated for each of the 32 bytes of the nonces.
- **LSB/MSB Patterns (32)**: Concentration of residues modulo $2^k$ and distribution of nonce bit-lengths.
- **Inter-sig Deltas (32)**: Bit-length distribution of the differences between sorted nonces.
- **Modular Residues (6)**: Chi-squared statistics for nonces modulo small primes.
- **Autocorrelation (16)**: Temporal correlation of nonce values at various lags.
- **Spectral Magnitude (32)**: FFT magnitudes of nonce bit-lengths.

### 5.3 Operation
Neural inference is triggered:
1.  **During Scoring**: To identify "hidden" anomalies that standard statistical tests (like Chi-Squared or LSB checks) miss.
2.  **During Striking**: As a high-signal filter to determine if intensive lattice reduction is likely to succeed.
