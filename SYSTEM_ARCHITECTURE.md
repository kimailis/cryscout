# CryScout System Architecture & Algorithmics (v3.5)

## 1. Overview
CryScout is a high-performance, distributed cryptanalytic suite designed to identify and exploit vulnerabilities in Bitcoin ECDSA signatures. Originally developed in Python, the system has transitioned to a multi-crate Rust architecture for maximum performance, concurrency, and reliability.

The primary objective of CryScout is to discover compromised wallets resulting from weak Random Number Generators (RNGs) used during transaction signing or wallet generation, thereby exposing the private key.

### 1.1 The "Real Data" Mandate
CryScout operates under a strict "Real Data Only" mandate. No simulated, fictional, or artificially generated target addresses are processed. Every address targeted by the system is mathematically verified to exist on the live Bitcoin blockchain and strictly enforces an active balance requirement of 2.0 to 4.0 BTC.

---

## 2. Cryptographic Algorithmics

Bitcoin uses the Elliptic Curve Digital Signature Algorithm (ECDSA) over the `secp256k1` curve.
- Curve Equation: $y^2 = x^3 + 7 \pmod p$
- Base Point: $G$
- Order of $G$: $n$

A signature consists of a pair $(r, s)$. During signing of a message hash $z$ with private key $d$:
1. A random nonce $k$ is chosen: $1 \le k < n$
2. $R = k \cdot G$
3. $r = R_x \pmod n$
4. $s = k^{-1} (z + r \cdot d) \pmod n$

### 2.1 The Vulnerability: Nonce Biases
The security of ECDSA relies entirely on the unpredictability and secrecy of the nonce $k$. Any bias or relationship between nonces exposes the private key $d$.

### 2.2 Attack Vector: Nonce Reuse (R-Reuse)
If the exact same nonce $k$ is used for two different messages ($z_1 \neq z_2$), the $r$ values will be identical ($r_1 = r_2$). The private key can be recovered:
$$k = \frac{z_1 - z_2}{s_1 - s_2} \pmod n$$
$$d = \frac{s_1 \cdot k - z_1}{r} \pmod n$$
**System implementation**: Explicitly checked in `Striker` Step 0 using normalized hex-string comparison across different `txids`.

### 2.3 Attack Vector: Nonce Relations
If an RNG generates related nonces, such as $k_2 = k_1 + \delta$ or $k_2 = c \cdot k_1$, algebraic manipulation can recover $d$.
- **Point Delta Scan**: $O(N \cdot \text{limit})$ search for additive offsets.
- **Optimized Ratio Scan**: $O(N \cdot \text{limit})$ Meet-in-the-Middle search using hash maps to identify multiplicative relations ($a \cdot k_i = b \cdot k_j$).

### 2.4 Attack Vector: Hidden Number Problem (HNP) via Lattice Reduction
If an RNG produces nonces with a known bias (e.g., the top 8 bits are always zero), this constitutes the Hidden Number Problem.
CryScout reformulates this into a Closest Vector Problem (CVP) and solves it using BKZ-20 (Block Korkine-Zolotarev) reduction.

---

## 3. Subsystems & Components

### 3.1 Core Infrastructure
- **`cryshub_rs` (The Hub)**: Central orchestration service. Manages worker lifecycles, resource pools, and handles inter-process signals.
- **`crypdash_rs` (The Dashboard)**: Ratatui-based TUI for real-time visualization of system statistics, active workers, and critical findings.
- **SQLite Database (`cryscout.db`)**: Central state repository. Standardized on `WAL` journal mode and `30s busy_timeout` to ensure stable concurrent access across 15+ workers.

### 3.2 Workers & Analyzers
- **`cryscout_worker_rs`**: A multi-mode worker:
    - **Scanner**: replenishes the target queue from dormant candidates.
    - **Analyzer**: Computes statistical features for target scoring.
    - **Scorer**: Enforces 2.0 to 4.0 BTC requirement and prioritizes "Easy Targets" (flawed PRNG signatures).
    - **Striker**: Executes the 6-stage Precision Strike sequence.
- **`address_analyzer_rs` (Fetcher)**: Extracts transaction signatures from the live blockchain via Mempool API. Optimized to ignore irrelevant low-balance addresses.
- **`wallet_scout_rs` (Global Scouter)**: High-speed mnemonic bruteforcer. Optimized for 2-core systems (single-thread mode) and focused strictly on Legacy (`1...`) and P2SH (`3...`) targets.
- **`neural_scout_rs` (Neural Autocorrect)**: Uses neural-guided failure patterns (Timestamp seeding, Low-entropy buffers) to focus brute-force power on the most vulnerable targets.

### 3.3 Phase II Precision Strike Suite
- **`physics_engine_rs`**: 
    - **Chaos Analyzer**: Calculates **Fractal Dimension** via 3D phase space mapping to detect non-random "Strange Attractors" ($D < 1.1$).
    - **Differential Ratio Scoring**: Identifies stable algebraic ratios indicative of LCGs.
- **`genotype_rs`**: Population-level clustering to identify shared "RNG DNA" across different wallet families.
- **`bias_detector_rs`**: ONNX-based inference (FFNN/LSTM) for identifying non-random signature sequences.

---

## 4. Scoring & Prioritization Strategy
The system prioritizes **Ease of Access** over **Total Balance**.
1.  **Low-Order Bit Bias**: Predictable LSBs provide optimal entry points for lattices.
2.  **RNG DNA Matches**: Targets sharing fingerprints with known broken implementations (Android, OpenSSL, etc.).
3.  **Era Context**: Heavy prioritization of 2009-2012 wallets (the "Era of Weak PRNGs").
4.  **Neural Confidence**: High non-randomness scores ($P > 0.9$) from the FFNN model.

---

## 5. Logic Flow for Each Target Address

When an address is targeted by the **Striker**, it undergoes the following 6-step sequence:

| Step | Module | Attack Type |
| :--- | :--- | :--- |
| **0/6** | Internal | **Nonce Reuse Check**: Identify $r_1 = r_2$ across different TXs. |
| **1/6** | `nonce_relation_rs` | **Algebraic Relations**: Delta/Ratio scanning ($O(N \cdot L)$). |
| **2/6** | `bias_detector_rs` | **Spectral Analysis**: FFT-based periodicity detection. |
| **3/6** | `lattice_attack_rs` | **Lattice Strike**: BKZ-20 reduction for biased nonces (HNP). |
| **4/6** | `physics_engine_rs` | **Chaos Analysis**: Fractal dimension and Attractor detection. |
| **5/6** | `bleichenbacher_fourier` | **Fourier Solver**: 4-list sum periodicity recovery. |
| **6/6** | `neural_inference` | **Pattern Match**: Final ONNX-based anomaly prediction. |

---

## 6. Resource Management & Scaling
To maintain high scouting speeds on resource-constrained systems (e.g., 2-core environments):
- **Worker Throttling**: `wallet_scout_rs` and `neural_scout_rs` are limited to **single-thread pools** to prevent CPU starvation of the high-priority Strike modules.
- **Sequential Striking**: Strike modules run sequentially within each Striker worker to maximize per-attack CPU cache efficiency.
- **DB Concurrency**: Global use of **WAL mode** and **30s busy_timeout** ensures zero-lock operation during high-intensity database activity.
