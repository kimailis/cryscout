# CryScout — Roadmap & Architecture

## Current State (v1.0)

### What We Have
| Module | Description | Status |
|---|---|---|
| `db_manager.py` | SQLite database (addresses, signatures, vulnerabilities, recovered keys) | ✅ Working |
| `api_client.py` | Multi-source Bitcoin API (mempool.space, blockchair, blockchain.info) | ✅ Working |
| `tx_preimage_reconstructor.py` | ECDSA sighash reconstruction (Legacy P2PKH + SegWit v0 BIP143) | ✅ Working |
| `lattice_nonce_analyzer.py` | LLL lattice reduction for HNP (Hidden Number Problem) | ✅ Working |
| `deep_scan.py` | Original deep scanner (R-reuse, lattice, polynonce, algebraic) | ✅ Working |
| `polynonce_attack.py` | Linear/quadratic polynomial nonce recurrence attacks | ✅ Working |
| `advanced_nonce_attacks.py` | Delta, multiplicative, LCG nonce relation attacks | ✅ Working |
| `weak_key_scanner.py` | Small keys, pattern keys, brainwallets, Android RNG | ✅ Working |
| `solve_cross_collision.py` | Cross-address R-value collision solver | ✅ Working |
| `crypservice.py` | Background scanning service (cycles through all attack types) | ✅ Working |
| `crypdash.py` | Curses-based terminal dashboard | ✅ Working |
| `cryscout_enhanced.py` | **NEW** — Enhanced 7-attack scanner with strict R-reuse, weak nonce, related nonce, half-half nonce | ✅ Working |
| `seed_guesser.py` | **NEW** — BIP39 mnemonic pattern guesser (6 strategies, 13K+ seeds) | ✅ Working |
| `vulnerability_scorer.py` | **NEW** — Statistical vulnerability scoring model (0-100 risk score) | ✅ Working |

### Database Contents
- **1,000 addresses** tracked (top Bitcoin holders + known targets)
- **908 unique ECDSA signatures** across 17 addresses
- **73 vulnerability findings** (LSB bias detections)
- **0 keys recovered** (yet)

### Key Findings So Far
1. Most top-value addresses are **truly dormant** — never spent, zero ECDSA signatures available
2. "R-reuse" detections were **false positives** from duplicate DB entries (fixed in enhanced scanner)
3. Addresses with signatures show **cryptographically proper nonce randomness** — no exploitable bias detected
4. The BIP39 seed guesser tested 13,227 seeds — none matched (wallets weren't created with trivially weak mnemonics)

---

## Phase 2 — Immediate Next Steps

### 2.1 Massive Brainwallet Dictionary Attack → `massive_brainwallet.py`
**Priority: HIGH** — Known to work historically. Many early Bitcoin addresses used SHA256(passphrase) as private keys.

- [x] Generate comprehensive wordlist (10M+ entries):
  - Common passwords (loads rockyou.txt / passwords.txt if present)
  - All English words + common misspellings
  - Number sequences (0–10M)
  - Keyboard patterns (`qwerty`, `asdfgh`, `zxcvbn`, etc.)
  - Famous quotes, song lyrics, movie lines
  - Bitcoin-related phrases (`satoshi`, `nakamoto`, `genesis`, etc.)
  - Leetspeak variations (`p4ssw0rd`, `b1tc01n`)
  - Date-based strings (`20090103`, `01/03/2009`)
  - Phone number patterns
- [ ] Implement batch GPU-accelerated SHA256 hashing (future)
- [x] Address comparison using set() lookup (O(1) per check)
- [x] Run against ALL 1,000 tracked addresses

### 2.2 Known-Vulnerable Address Database → `known_vuln_scanner.py`
**Priority: HIGH** — Public databases exist of addresses with confirmed weak keys.

- [x] Generate Debian OpenSSL weak keys (CVE-2008-0166):
  - SHA256(PID bytes) for PIDs 1-32768
  - SHA256(PID string) for PIDs 1-32768
  - Direct PID as key (1-32768)
  - MD5(PID) padded to 32 bytes
  - Combined PID+UID variants (root, user, nobody)
- [x] Blockchain Bandit sequential keys (1 to 2^24, expanding each cycle)
- [x] Known compromised hex patterns (repeated bytes, powers of 2, Fibonacci, famous constants)
- [x] Bitcoin Puzzle range boundaries
- [x] Cross-reference ALL against our tracked addresses

### 2.3 Expanded Signature Collection → `expanded_sig_fetch.py` + `api_client.py`
**Priority: HIGH** — More signatures = better lattice attack surface.

- [x] Fix API rate limiting strategy (exponential backoff, user agent rotation)
- [x] Add Esplora API (Blockstream) as 4th source
- [x] Implement raw Bitcoin RPC connection for local full node (if available)
- [x] Target addresses with high TX count but few collected sigs:
  - `12ib7dAp` — 250 TXs, only 4 sigs collected (31K BTC)
  - `15Z5YJaa` — 138 TXs, only 60 sigs (8K BTC)
  - `17rm2dvb` — 118 TXs, only 1 sig (20K BTC)
  - `1GR9qNz7` — 108 TXs, only 1 sig (16K BTC)

---

## Phase 3 — Advanced Techniques

### 3.1 Neural Network Nonce Anomaly Detector
**Priority: MEDIUM** — Detect hidden patterns that statistical tests miss.

Architecture:
```
Input Features (per signature set):
├── R-value bit distribution (256 features)
├── R-value byte entropy (32 features)
├── LSB pattern vector (16 features)
├── MSB pattern vector (16 features)
├── Inter-signature R deltas (N features)
├── R-value modular residues (mod 2,3,5,7,11,13)
├── Autocorrelation coefficients
└── Frequency domain (FFT) features

Model: Binary Classifier
├── Input → Dense(512, ReLU) → Dropout(0.3)
├── Dense(256, ReLU) → Dropout(0.3)
├── Dense(128, ReLU)
├── Dense(64, ReLU)
└── Dense(1, Sigmoid) → P(vulnerable)

Training Data:
├── Positive: Synthetically generated weak nonces (biased, LCG, repeated)
└── Negative: Cryptographically random nonces (from /dev/urandom)
```

- [ ] Generate synthetic training dataset (100K+ samples)
- [ ] Train binary classifier to detect nonce weakness
- [ ] Apply to real signature sets — flag addresses with high P(vulnerable)
- [ ] Use attention mechanism to identify which specific signatures are most suspicious
- [ ] Ensemble with statistical scorer for final ranking

### 3.2 GPU-Accelerated LLL Lattice Reduction
**Priority: MEDIUM** — Current pure-Python LLL is the bottleneck.

- [ ] Integrate `fpylll` (FPLLL Python bindings) — industry-standard LLL implementation
- [ ] Try BKZ (Block Korkine-Zolotarev) reduction for better results than LLL
- [ ] Implement progressive lattice dimension increase (start small, expand if no result)
- [ ] Parallelize across multiple bias assumptions simultaneously

### 3.3 Pollard's Kangaroo / Rho for Partial Key Recovery
**Priority: MEDIUM** — When we know partial information about the key.

- [ ] Implement Pollard's kangaroo algorithm for bounded key search
- [ ] Use when lattice narrows key to a range (e.g., 2^40 candidates)
- [ ] Multi-threaded with distinguished points optimization

### 3.4 Taproot / Schnorr Signature Analysis
**Priority: LOW** — Newer addresses use Schnorr signatures (different math).

- [ ] Implement Schnorr signature extraction from P2TR inputs
- [ ] Adapt nonce bias detection for Schnorr (same HNP principle applies)
- [ ] Track bc1p... addresses in the database

---

## Phase 4 — Infrastructure & Scale

### 4.1 Full Node Integration
- [ ] Connect to local Bitcoin Core node via RPC
- [ ] Parse raw blocks for signature data (bypass API rate limits)
- [ ] Real-time mempool monitoring for new signatures from tracked addresses

### 4.2 Distributed Scanning
- [ ] Worker-based architecture for parallel brainwallet hashing
- [ ] Partition key space across multiple machines
- [ ] Redis/PostgreSQL for shared state

### 4.3 Monitoring & Alerts
- [ ] Telegram/Discord bot for instant alerts on key recovery
- [ ] Web dashboard replacement for `crypdash.py`
- [ ] Automated fund sweep + secure storage on recovery

---

## Attack Vector Effectiveness Matrix

| Attack | Requires | Best Against | Success Probability |
|---|---|---|---|
| Brainwallet (SHA256) | Address only | Human-chosen passphrases | ★★★☆☆ |
| BIP39 Seed Guess | Address only | Predictable mnemonics | ★★☆☆☆ |
| Weak Key Scan (small k) | Address only | Early/buggy wallet software | ★★☆☆☆ |
| R-Value Reuse | ≥2 sigs, same R, diff Z | Broken RNG (RFC 6979 not used) | ★★★★★ |
| Lattice HNP (biased nonce) | ≥4 sigs with bias | Weak RNG, partial nonce leak | ★★★☆☆ |
| Polynonce (linear/quad) | ≥4 consecutive sigs | LCG/polynomial nonce generation | ★★★☆☆ |
| Algebraic (delta/mult) | ≥2 sigs same TX | Deterministic nonce bugs | ★★★☆☆ |
| Neural Net Anomaly | ≥10 sigs | Unknown/novel weakness patterns | ★★☆☆☆ |
| Pollard's Kangaroo | Partial key info | Combined with lattice partial result | ★★★★☆ |

---

## How to Run

```bash
# Full enhanced scan (all attacks, skip API fetch)
python3 cryscout_enhanced.py 50 --skip-fetch

# Brainwallet + seed guess only
python3 cryscout_enhanced.py 50 --skip-fetch --brainwallet-only

# Seed guesser (BIP39)
python3 seed_guesser.py

# Vulnerability scoring (prioritize targets)
python3 vulnerability_scorer.py 30

# Original dashboard
python3 crypdash.py

# Background service (continuous scanning)
python3 crypservice.py

# Lattice attack on specific address
python3 lattice_nonce_analyzer.py <address> [bias_bits]

# Polynonce attack
python3 polynonce_attack.py [address]

# Weak key scan (small keys up to 2^20)
python3 weak_key_scanner.py [max_key]
```

---

## File Structure
```
cryscout/
├── Core
│   ├── db_manager.py              # SQLite database operations
│   ├── api_client.py              # Multi-source Bitcoin API client
│   ├── tx_preimage_reconstructor.py  # ECDSA sighash reconstruction
│   └── cryscout.db                # SQLite database
│
├── Scanners
│   ├── cryscout_enhanced.py       # Enhanced 7-attack deep scanner ★
│   ├── deep_scan.py               # Original deep scanner
│   ├── weak_key_scanner.py        # Weak key pattern scanner
│   ├── brainwallet_scanner.py     # Dictionary-based brainwallet scanner
│   ├── seed_guesser.py            # BIP39 mnemonic guesser ★
│   └── master_scanner.py          # Coordinating scanner
│
├── Attacks
│   ├── lattice_nonce_analyzer.py  # LLL lattice for HNP
│   ├── polynonce_attack.py        # Polynomial nonce recurrence
│   ├── advanced_nonce_attacks.py  # Delta, multiplicative, LCG
│   ├── solve_cross_collision.py   # Cross-address R collision
│   └── recover_key.py             # Key recovery utilities
│
├── Analysis
│   ├── vulnerability_scorer.py    # Statistical vulnerability scoring ★
│   ├── nonce_bias_detector.py     # Nonce bias detection
│   ├── nonce_checker.py           # Nonce validation
│   └── global_rng_check.py        # RNG quality analysis
│
├── Service
│   ├── crypservice.py             # Background scanning service
│   ├── crypdash.py                # Terminal dashboard (curses)
│   └── crypdash                   # Launcher script
│
├── Data
│   ├── master_address_tracking.csv
│   ├── dormant_addresses.csv
│   ├── dictionary.txt
│   ├── extended_dictionary.txt
│   ├── sigs_*.json                # Cached signature files
│   └── vulnerability_scores.json
│
├── ROADMAP.md                     # This file ★
├── summary_steps.md               # Original methodology notes
└── requirements.txt               # Python dependencies
```

*★ = New in this session*
