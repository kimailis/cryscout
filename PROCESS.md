# CryScout Advanced Cryptanalysis Process

This document outlines the refined process for identifying and exploiting cryptographic vulnerabilities in high-value Bitcoin addresses.

## 1. High-Potential Target Identification
The system now focuses on "Real Targets" — addresses that are not only high-balance but have a confirmed history of spending transactions.
- **Script**: `find_real_targets.py`
- **Method**: Filters addresses from the top 500 list that have `Spent/Active` status and multiple spending signatures.
- **Top Targets identified**:
    - `1AV4KGCsvtPZ9tG7hvwgb85wJyFd9xdpFv` (397 sigs)
    - `13kxWCuDWN1gGSe2vPmsSBVXyPfYLMh6M4` (313 sigs)
    - `1FdPpELnjHfwSM4Nvi7LdYS4S4GVGsLUQY` (240 sigs)
    - `15Z5YJaaNSxeynvr6uW6jQZLwq3n1Hu6RX` (169 sigs)

## 2. Database Boosting & Prioritization
To ensure background workers (fetcher, analyzer, striker) focus on the most viable targets, we implemented a boosting mechanism.
- **Script**: `boost_targets.py`
- **Action**: Resets the `sigs_fetched` and `analyzed` flags for priority addresses and forces them to the top of the queue by manipulating `last_updated` timestamps.

## 3. Public Key Recovery
Standard blockchain APIs often don't provide the public key for an address unless it's in a recent transaction. We implemented a manual recovery tool.
- **Script**: `extract_pubkey_from_address.py`
- **Method**: Uses ECDSA point recovery from a single (r, s, z) signature tuple to derive the matching public key (compressed or uncompressed).

## 4. Advanced Signature Analysis
We developed a suite of targeted analysis scripts to detect non-obvious biases:
- **LSB/MSB Bias**: `check_manual_bias.py`, `check_msb_bias.py`
- **Distribution Analysis**: `check_r_dist.py`
- **Lattice Attacks**: Enhanced `solve_hnp` with LSB-specific transforms in `advanced_lattice.py` and `lattice_lsb_analyzer.py`.
- **High-Precision Solver**: `offline_lattice_analyzer_mpmath.py` for dealing with small biases across hundreds of signatures.

## 5. Cross-Transaction Relation Attacks
One of the most powerful vectors developed is the optimized relation scanner.
- **Script**: `cross_tx_relations_scanner.py`
- **Optimizations**:
    - Uses Elliptic Curve point addition/multiplication to search for `k_i = k_j + delta` and `k_i = c * k_j`.
    - Implements a hash-map based lookup for $O(N \cdot range)$ complexity instead of $O(N^2)$.
    - Automatically recovers the private key upon finding a valid relation.

## 6. Worker Suite Management
The background infrastructure was consolidated for efficiency:
- **Fetcher**: Continuously extracts signatures via mempool.space and blockchain.info.
- **Analyzer**: Runs statistical tests and prepares lattice bases for any flagged addresses.
- **Striker**: Executes intensive BKZ/LLL reduction and Pollard's Kangaroo searches on high-probability targets.

## 7. Results & Verification
All recovered keys are stored in the `recovered_keys` table and verified against the target address hash before being reported.
