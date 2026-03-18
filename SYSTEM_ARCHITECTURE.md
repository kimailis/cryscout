# CryScout System Architecture & Algorithmics

## 1. Overview
CryScout is a high-performance, distributed cryptanalytic suite designed to identify and exploit vulnerabilities in Bitcoin ECDSA signatures. Originally developed in Python, the system has transitioned to a multi-crate Rust architecture (v3.2) for maximum performance, concurrency, and reliability.

The primary objective of CryScout is to discover compromised wallets resulting from weak Random Number Generators (RNGs) used during transaction signing or wallet generation, thereby exposing the private key.

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
If the exact same nonce $k$ is used for two different messages ($z_1 \neq z_2$), the $r$ values will be identical ($r_1 = r_2$). The private key can be trivially recovered:
$$k = \frac{z_1 - z_2}{s_1 - s_2} \pmod n$$
$$d = \frac{s_1 \cdot k - z_1}{r} \pmod n$$

### 2.3 Attack Vector: Nonce Relations
If an RNG generates related nonces, such as $k_2 = k_1 + \delta$ or $k_2 = c \cdot k_1$, algebraic manipulation can recover $d$.
CryScout implements an $O(N)$ Point Delta Scan for additive relations and $O(N^2)$ Point Ratio Scan for multiplicative relations.

### 2.4 Attack Vector: Hidden Number Problem (HNP) via Lattice Reduction
If an RNG produces nonces with a known bias (e.g., the top 8 bits are always zero), this constitutes the Hidden Number Problem.
CryScout reformulates this into a Closest Vector Problem (CVP) and solves it using BKZ-20 (Block Korkine-Zolotarev) reduction on a $(m+2) \times (m+2)$ lattice.

---

## 3. Subsystems & Components

### 3.1 Core Infrastructure
- **`cryshub_rs` (The Hub)**: Central orchestration service. Manages worker lifecycles, monitors system health (CPU/RAM), and handles inter-process communication via `service_signal.txt`.
- **`crypdash_rs` (The Dashboard)**: Ratatui-based TUI for real-time visualization of global statistics, active workers, potential targets, and recovered keys. Includes a `busy_timeout` mechanism for SQLite concurrency.
- **SQLite Database (`cryscout.db`)**: Central state repository storing `addresses`, `signatures`, `vulnerabilities`, `worker_status`, and `recovered_keys`.

### 3.2 Workers & Analyzers
- **`cryscout_worker_rs`**: A multi-mode worker:
    - **Scanner**: Monitors target queue; triggers replenishment if unscanned high-priority targets < 5.
    - **Analyzer**: (Stubbed) Performs initial statistical passes.
    - **Scorer**: Calculates multi-factor risk scores.
    - **Striker**: Executes the High-Precision Strike sequence.
- **`address_analyzer_rs`**: Fetches signatures and reconstructs message hashes (`z-values`).
- **`wallet_scout_rs`**: High-speed BIP39 mnemonic scouter (~150k kps).

### 3.3 Attack Modules (Precision Strike Suite)
- **`nonce_relation_rs`**: 
    - **Point Delta Scan**: Uses $k \cdot G = (s^{-1} z \cdot G + s^{-1} r \cdot Q)$ to find $k_i = k_j + \delta$ in $O(N \cdot \text{limit})$.
    - **Polynonce Linear**: Solves quadratic modular equations for linear nonce recurrences in $O(N)$.
    - **Point Ratio Scan**: Checks for $a \cdot k_i = b \cdot k_j$ in $O(N^2 \cdot \text{limit}^2)$.
- **`lattice_attack_rs`**: Implements BKZ-20 reduction on an HNP lattice with a floating-point (f64) Gram-Schmidt basis.
- **`bias_detector_rs`**: 
    - **Spectral Bias**: Uses FFT to identify periodic peaks in bit-length or value distributions.
    - **Neural Anomaly**: Runs ONNX inference (FFNN/LSTM) on 438-dimensional feature vectors.
- **`physics_engine_rs` (Phase II)**:
    - **Chaos Analyzer**: Maps 3 sequential nonces into 3D phase space to calculate the **Fractal Dimension**; identifies "Strange Attractors" (Lorenz) in PRNG outputs.
    - **Time-Coupled Entropy**: Detects covariance between transaction timing ($\Delta t$) and nonce distance ($\Delta r$).
    - **Bit-Plane Spectral FFT**: Isolates bits 0-15 and performs FFT to detect periodic bit-leaks masked by bit-noise.
    - **Signature Drift**: Detects "Fixed-Seed Startup" bugs by analyzing bias resets across sessions.
    - **Differential Ratio Scoring**: Identifies stable algebraic ratios between consecutive $r$-values (indicative of LCGs).
- **`genotype_rs` (Phase II)**:
    - **Population Fingerprinting**: Generates a **512-D Fingerprint Vector** (LSB/MSB profile, Byte Entropy Map, FFT Peaks, Delta-R distribution) for each address.
    - **Clustering Engine**: Employs **K-Means Clustering** to group addresses sharing the same "RNG DNA," enabling bulk solving of entire wallet families.
- **`bleichenbacher_fourier`**: Fourier-based solver for detecting subtle periodicities across large signature sets using 4-list sum combinations.

---

## 4. Logic Flow for Each Target Address

When an address is targeted by the **Striker**, it undergoes the following deterministic sequence:

### Step 1: Data Preparation
1.  **Fetch Signatures**: All unique $(r, s, z)$ tuples for the address are retrieved from the `signatures` table.
2.  **Generate Temp File**: Signatures are serialized to `temp_sigs_<address>.json`.
3.  **Extract Features**: A 438-dimensional feature vector is generated (bit counts, byte entropy, LSB patterns, deltas, modular residues, autocorrelation, FFT).

### Step 2: The Precision Strike Sequence
| Sequence | Module | Logic | Result |
| :--- | :--- | :--- | :--- |
| **1/5** | `nonce_relation_rs` | Additive Delta Scan ($O(N)$), Polynonce Linear, Multiplicative Ratio Scan ($O(N^2)$). | `recovered_keys` |
| **2/5** | `bias_detector_rs` | FFT Spectral Analysis on bit-patterns. | `vulnerabilities` |
| **3/5** | `lattice_attack_rs` | Construct $(n+2) \times (n+2)$ HNP lattice; execute BKZ-20 reduction. | `recovered_keys` |
| **4/5** | `bleichenbacher_fourier` | Generate 4-list combinations; perform Fourier search for periodic hit $d$. | `vulnerabilities` |
| **5/5** | `neural_inference` | ONNX FFNN Prediction ($P(\text{vulnerable})$) + LSTM Spectral Prediction. | `vulnerabilities` |

### Step 3: Key Verification & Logging
- Any recovered private key $d$ is immediately verified by deriving the public key $Q = d \cdot G$ and hashing it to ensure it matches the target address.
- Verified keys are stored in `recovered_keys`.
- Detections without an immediate key are logged as `High` severity findings in `vulnerabilities`.
- The address is marked `sigs_scanned = 1` to prevent redundant strikes.

---

## 5. Neural Network & Feature Details

### 5.1 FFNN Feature Extraction (438 Dimensions)
- **Bit Distribution (256)**: Normalized frequency of each bit position.
- **Byte Entropy (32)**: Shannon entropy per byte.
- **LSB/MSB Patterns (32)**: Concentration of residues and bit-lengths.
- **Inter-sig Deltas (32)**: Statistics on differences between sorted nonces.
- **Modular Residues (6)**: Chi-squared stats modulo small primes {2, 3, 5, 7, 11, 13}.
- **Autocorrelation (16)**: Temporal correlation of nonce values at various lags.
- **FFT Magnitudes (32)**: Frequency domain features of the bit-length sequence.

### 5.2 LSTM Spectral Predictor
- **Input**: Sequence of the last 20 nonces (64 bits each).
- **Logic**: Predicts the bit-pattern of the *next* nonce based on spectral history.
- **Metric**: `Avg Confidence` > 0.7 triggers a high-predictability vulnerability finding.

---

## 6. System Flowchart (Mermaid)

```mermaid
graph TD
    classDef striker fill:#fbf,stroke:#333,stroke-width:2px;
    classDef db fill:#eee,stroke:#333,stroke-width:1px,stroke-dasharray: 5 5;

    A[Target Queue] -->|Striker Claims| B(Fetch Signatures)
    B --> C[temp_sigs_addr.json]
    
    subgraph Precision Strike
        C --> D1[1. Nonce Relation]:::striker
        C --> D2[2. Spectral FFT]:::striker
        C --> D3[3. BKZ-20 Lattice]:::striker
        C --> D4[4. Fourier Analysis]:::striker
        C --> D5[5. Neural ONNX]:::striker
    end
    
    D1 & D3 -->|Key Recovered| E{Verify Key}
    E -->|Valid| F[(Database: recovered_keys)]:::db
    E -->|Invalid| G[Log False Positive]
    
    D2 & D4 & D5 -->|Bias Found| H[(Database: vulnerabilities)]:::db
    
    Precision Strike --> I[Mark sigs_scanned = 1]
```
