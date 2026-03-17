# CryScout Python System Summary

This document provides a comprehensive archival record of the Python-based implementation of CryScout before its transition to the Rust-based `crypdash_rs`. It categorizes all 171 `.py` files into logical groups based on their purpose and functionality.

---

## 1. Core & Infrastructure
*Base services, database management, and distributed worker orchestration.*

- **api_client.py**: Multi-source Bitcoin API client supporting mempool.space, blockchair, and Esplora with automatic failover.
- **base_worker.py**: Abstract base class defining the lifecycle and communication protocol for distributed worker nodes.
- **crypservice.py**: Core system service for managing background processes, health checks, and service monitoring.
- **cryshub.py**: Centralized communication hub for orchestrating tasks and message passing between workers.
- **db_manager.py**: Primary interface for the SQLite database, handling all address, signature, and vulnerability persistence.
- **init_db.py**: Script to initialize the database schema, indexes, and default configuration tables.
- **sync_db.py**: Maintenance utility to synchronize vulnerability flags and findings between different database tables.
- **worker_analyzer.py**: Distributed worker node specialized in performing compute-intensive cryptographic analysis.
- **worker_bruteforce.py**: Distributed worker node dedicated to range-based brute-force attacks on private keys.
- **worker_cluster.py**: Worker node responsible for clustering signatures and identifying multi-transaction patterns.
- **worker_fetcher.py**: Asynchronous worker node for high-speed signature collection from various blockchain APIs.
- **worker_forensic.py**: Intensive worker node for deep forensic reconstruction and analysis of address histories.
- **worker_neural.py**: Worker node that executes neural network inference to detect non-obvious nonce anomalies.
- **worker_scanner.py**: General-purpose worker node for initial address discovery and broad vulnerability scanning.
- **worker_striker.py**: High-priority worker node for executing immediate recovery attacks once a vulnerability is confirmed.

---

## 2. Scanners & Discovery
*Tools for identifying targets, scraping rich lists, and extracting signatures.*

- **boost_targets.py**: High-priority scanner targeting specific high-value addresses identified in the project roadmap.
- **cryscout_enhanced.py**: Advanced multi-vector scanner that orchestrates de-duplication, validation, and complex attack sequences.
- **deep_scan.py**: Comprehensive scanner for dormant and high-value addresses, executing all available attack vectors.
- **expanded_sig_fetch.py**: Collection utility focusing on addresses with high transaction counts but low signature coverage.
- **fetch_dormant_targets.py**: Scraper for BitInfoCharts' list of high-value Bitcoin addresses dormant for over 7 years.
- **fetch_older_era.py**: Discovery tool for Satoshi-era P2PK addresses and early blockchain legacy outputs.
- **fetch_rich_targets.py**: Scraper for the top richest Bitcoin addresses to ensure a steady supply of high-value targets.
- **fetch_sigs_for_targets.py**: Batch fetching utility that prioritizes signature collection for the most promising targets.
- **fetch_target_sigs.py**: Specialized script for exhaustive signature collection from specific high-priority target addresses.
- **harvest_signatures.py**: Blockchain scanner designed to extract signatures directly from P2PK and early legacy transactions.
- **master_scanner.py**: Top-level orchestration script for the entire scanning lifecycle, from discovery to analysis.
- **replenish_targets.py**: Automated service for refreshing the target database with fresh, high-value dormant addresses.
- **scanner_forensic.py**: Forensic tool for deep investigation into transaction patterns and signature characteristics.
- **signature_extractor.py**: Utility for parsing and extracting DER-encoded ECDSA signatures from raw blockchain data.
- **tx_preimage_reconstructor.py**: Reconstructs transaction preimages (Z-values) required for ECDSA signature verification.

---

## 3. Cryptographic Attacks
*Implementations of lattice reductions, algebraic attacks, and brute-force methods.*

- **advanced_lattice.py**: Implements BKZ reduction and progressive dimension attacks for the Hidden Number Problem (HNP).
- **advanced_nonce_attacks.py**: Executes complex LCG, delta, and multiplicative attacks on nonce generation sequences.
- **attack_small_r.py**: Brute-force solver for private keys when signatures use extremely small R-values (nonce bias).
- **attack_small_r_fpylll.py**: High-performance implementation of the small R attack using the `fpylll` library.
- **brainwallet_scanner.py**: Scans for weak private keys generated from common brainwallet passphrases and patterns.
- **bruteforce_deterministic_k.py**: Analyzes signatures for deterministic nonce (RFC 6979) usage and identifies related weaknesses.
- **bsgs_34bit.py**: Baby-step Giant-step implementation for recovering keys within a 34-bit bounded range.
- **check_bruteforce_targets.py**: Identifies and prepares candidates for range-based brute-force attacks.
- **check_bruteforce_targets_detail.py**: Detailed analysis of potential brute-force targets with specific bit-range estimates.
- **cluster_attack_lattice.py**: Performs lattice reduction on groups of signatures clustered by nonce similarity.
- **fast_lattice_analyzer.py**: Accelerated lattice reduction tool for rapid vulnerability assessment of specific addresses.
- **fast_lll.py**: Optimized implementation of the LLL algorithm using high-precision floating-point arithmetic.
- **find_all_r_collisions.py**: Global search utility for identifying R-value (nonce) reuse across the entire signature database.
- **find_cross_address_collisions.py**: Detects instances where the same nonce was used by different Bitcoin addresses.
- **find_real_r_reuse.py**: Confirms and isolates instances of true nonce reuse with differing message hashes.
- **lattice_lsb_analyzer.py**: Specialized lattice attack for signatures exhibiting bias in the least significant bits of the nonce.
- **lattice_nonce_analyzer.py**: Primary implementation of the HNP lattice attack for recovering private keys from biased nonces.
- **offline_lattice_analyzer.py**: Standalone tool for running lattice attacks on local JSON-formatted signature datasets.
- **offline_lattice_analyzer_mpmath.py**: Lattice analyzer utilizing `mpmath` for arbitrary-precision arithmetic in LLL reduction.
- **pollard_kangaroo.py**: Implementation of Pollard's Kangaroo algorithm for solving the discrete log problem in a bounded range.
- **polynonce_attack.py**: Algebraic attack that exploits polynomial relationships between nonces in a sequence.
- **recover_key.py**: Utility for deriving the final private key from confirmed collisions or lattice reduction outputs.
- **seed_guesser.py**: Massive-scale generator and checker for common BIP39 mnemonic seed patterns and phrases.
- **solve_15Z5YJaa.py**: Customized attack implementation with specific parameters for the high-value 15Z5YJaa address.
- **solve_15Z5YJaa_v2.py**: Iterative improvement on the 15Z5YJaa attack using refined lattice dimensions and bias assumptions.
- **solve_1GR9qNz7.py**: Targeted attack script for the 1GR9qNz7 address using specialized nonce-relation solvers.
- **solve_1av4.py**: Specialized solver for the 1AV4... address group based on specific observed nonce biases.
- **solve_1qla.py**: Custom attack implementation for the 1qla... address using observed LSB patterns.
- **solve_1qla_fpylll.py**: Refined 1qla... attack utilizing `fpylll` for more efficient BKZ reduction.
- **solve_bc1q.py**: Specialized attack targeting SegWit (Bech32) addresses with observed nonce anomalies.
- **solve_bias_fixed_k.py**: Attack script for cases where a portion of the nonce (k) is fixed across signatures.
- **solve_cross_collision.py**: Automates key recovery from R-collisions found between different addresses or transactions.
- **solve_db_r_reuse.py**: Batch key recovery script that processes all confirmed R-reuse instances in the database.
- **solve_deep_16.py**: Deep lattice attack using 16 signatures to recover keys from subtle nonce biases.
- **solve_deep_22.py**: Extended lattice attack using up to 22 signatures for higher success rates on narrow biases.
- **solve_deep_22_v3.py** through **solve_deep_22_v7**: Iterative variations of the deep 22-signature lattice attack for different target profiles.
- **solve_deep_bias.py**: Advanced solver targeting extremely subtle nonce distribution biases in high-value targets.
- **solve_modular_bias.py**: Lattice solver for nonces that exhibit bias modulo a specific non-power-of-two value.
- **solve_related.py**: Recovers private keys from signatures with known linear relationships between their nonces.
- **solve_related_fast.py**: High-speed implementation of the related-nonce recovery attack.
- **solve_reuse.py**: Simple recovery tool for classic R-reuse (same nonce, different message).
- **try_lattice_13kx.py**: Experimental lattice attack configuration for the 13kx... address.
- **try_lattice_152k.py**: Experimental lattice attack configuration for the 152k... address.
- **try_lattice_batch.py**: Automated utility for testing multiple lattice configurations against a target.
- **try_lsb_lattice.py**: Experimental test script for LSB-specific lattice reduction parameters.
- **try_nonce_delta.py**: Test script for identifying and exploiting fixed-delta relationships between nonces.
- **try_nonce_lcg.py**: Experimental solver for nonces generated using a Linear Congruential Generator.
- **try_nonce_relation.py** through **try_nonce_relation_v7**: Iterative experimental scripts for testing various algebraic nonce relations.
- **warpwallet_scanner.py**: Specialized scanner for WarpWallet vulnerabilities using high-iteration scrypt and PBKDF2.
- **weak_key_scanner.py**: Checks for known weak private key patterns, including Debian SSL and sequential hex patterns.

---

## 4. Analysis & Statistical Tools
*Bias detection, RNG quality checks, and forensic analysis.*

- **analyze_addresses.py**: Main statistical analysis tool for evaluating the vulnerability profile of tracked addresses.
- **analyze_nonce_msb.py**: Specifically detects Most Significant Bit (MSB) bias in signature nonces.
- **check_15Z5YJaa_reuse.py**: Forensic analysis of nonce usage patterns for the high-priority 15Z5YJaa address.
- **check_address_bias.py**: Performs a suite of statistical tests on a single address to detect cryptographic bias.
- **check_all_lsb_bias.py**: System-wide batch analyzer for identifying Least Significant Bit (LSB) bias across all targets.
- **check_bc1ql5hl.py**: Specialized analysis for the high-value SegWit address bc1ql5hl.
- **check_bc1ql5hl_db.py**: Database-integrated analysis for address bc1ql5hl tracking its findings over time.
- **check_fft_bias.py**: Uses Fast Fourier Transform (FFT) to identify periodic or spectral biases in nonce distributions.
- **check_lsb_all.py**: Comprehensive scanner for LSB bias detection using multiple statistical thresholds.
- **check_lsb_bias.py**: Basic statistical utility for detecting LSB-fixed or biased nonces.
- **check_lsb_bias_json.py**: Utility for analyzing LSB bias in signatures stored in local JSON files.
- **check_lsb_system.py**: Advanced detector that models LSB bias as a system of linear equations for validation.
- **check_msb_bias.py**: Database-wide scanner for Most Significant Bit (MSB) bias in collected signatures.
- **check_pubkey_address.py**: Utility to verify and derive Bitcoin addresses from raw public keys and vice-versa.
- **check_r_dist.py**: Statistical analysis of the distribution of R-values to identify non-random patterns.
- **check_r_reuse_segwit.py**: Specialized scanner for R-reuse specifically in Bech32 and SegWit-wrapped transactions.
- **check_recent_addresses.py**: Monitors and analyzes recently active high-value addresses for immediate vulnerabilities.
- **check_sigs_bc1ql5hl.py**: Detailed signature inspection tool for address bc1ql5hl.
- **check_target_bias.py**: Evaluation tool for assessing the attack surface of a target based on its signature history.
- **check_tx_nonces.py**: Diagnostic tool for analyzing nonces within specific individual transactions.
- **check_unspendable.py**: Heuristic tool to identify unspendable, burn, or script-locked addresses to avoid wasted resources.
- **check_wallet_label.py**: Identifies likely wallet software or signing libraries based on signature fingerprints.
- **clean_and_analyze.py**: Pre-processing script for cleaning raw signature data and performing initial bias detection.
- **detect_custom_bias.py**: Scans for custom, user-defined, or non-obvious bias patterns in signature nonces.
- **detect_nonce_lsb_bias.py**: Dedicated utility for identifying LSB bias in nonces from JSON datasets.
- **find_full_lsb_bias.py**: Searches for signatures where a significant portion of the nonce LSBs are consistently fixed.
- **global_rng_check.py**: System-wide audit tool for identifying PRNG failures that impact multiple unrelated addresses.
- **investigate_deep_bias.py**: Deep dive forensic tool for investigating extremely subtle biases in high-value targets.
- **library_fingerprinter.py**: Fingerprints signing libraries (e.g., OpenSSL, BitcoinJS) based on observed nonce characteristics.
- **nonce_bias_detector.py**: General-purpose detector for identifying various forms of ECDSA nonce bias.
- **nonce_checker.py**: Validation tool for checking nonces against statistical models of randomness.
- **reverse_entropy_analyzer.py**: Advanced cryptanalytic tool for measuring the entropy and predictability of nonces.
- **scan_active_bias.py**: Monitors the mempool and recent blocks for real-time nonce bias in active transactions.
- **schnorr_analyzer.py**: Adapts HNP and lattice analysis for Taproot (Schnorr) signatures.
- **verify_1feex.py**: Targeted verification script for the 1Feex... address's signature history.
- **verify_rng.py**: Diagnostic tool for verifying the output quality of Random Number Generators in various wallets.
- **vulnerability_scorer.py**: Statistical model that assigns a vulnerability score to addresses based on multiple bias signals.
- **weak_pubkey_check.py**: Checks for weak or non-standard public keys, such as those with small X-coordinates or known properties.

---

## 5. Machine Learning / Neural Networks
*Models and data preparation for AI-driven anomaly detection.*

- **convert_to_onnx.py**: Utility for converting trained PyTorch neural network models into the ONNX format for deployment.
- **nonce_neural_detector.py**: Employs deep learning (FFN and LSTM) to detect non-obvious patterns and spectral biases in nonces.

---

## 6. Dashboards & UI
*Visual monitoring and orchestration interfaces.*

- **crypdash.py**: Main terminal-based dashboard for system-wide status monitoring and manual orchestration.
- **miner_dash.py**: Specialized curses dashboard for monitoring the internal mining and block parsing processes.

---

## 7. Utilities & One-off Scripts
*Maintenance, data migration, and specific forensic tasks.*

- **bitcoin_miner.py**: Simple research miner used for testing transaction parsing and block generation logic.
- **cache_sigs.py**: Caches reconstructed signatures from the preimage service to local JSON files for offline analysis.
- **check_db.py**: Debugging utility for direct inspection of the SQLite database tables and record counts.
- **check_db_summary.py**: Generates a high-level statistical summary of findings and database health.
- **check_db_vulnerabilities.py**: Runs a comprehensive suite of vulnerability audits across the entire database.
- **check_inputs.py**: Diagnostic script for transaction input parsing and signature extraction verification.
- **check_inputs_v2.py** & **check_inputs_v3.py**: Improved versions of the input parsing diagnostic tool.
- **check_json_bias.py**: Utility for performing bias checks on signatures stored in JSON files.
- **check_manual_bias.py**: Tool for manually inspecting and verifying potential bias findings.
- **cluster_manager.py**: Manages the grouping of signatures and addresses into clusters for pattern analysis.
- **combine_data.py**: Utility for merging and de-duplicating signature data from multiple CSV sources.
- **cross_tx_delta_optimized.py**: High-performance implementation of the cross-transaction delta relationship scanner.
- **dump_sigs.py**: Simple utility to dump all signatures for a specific address to the console.
- **enrich_dictionary.py**: Expands the brainwallet dictionary with historical quotes, patterns, and literary phrases.
- **extract_data.py**: General-purpose blockchain data extraction script.
- **extract_pubkey.py**: Extracts compressed or uncompressed public keys from transaction scripts.
- **extract_pubkey_from_address.py**: Recovers public keys by searching the blockchain history for an address's first spend.
- **extract_tx_sigs.py**: Parses transaction hex to extract signatures, public keys, and message hashes.
- **extract_tx_sigs_v2.py**: Improved transaction signature extractor with better SegWit support.
- **find_all_a.py**: Finds algebraic constants and patterns in nonce generation sequences.
- **find_all_spending_txids.py**: Retrieves all transaction IDs where a given address acted as an input.
- **find_lsb_clique.py**: Identifies groups of signatures that share identical LSB patterns, indicating common weaknesses.
- **find_lsb_d.py**: Utility to solve for the private key given a known LSB bias and fixed nonce bits.
- **find_lsb_subset.py**: Filters and extracts subsets of signatures that meet specific LSB bias criteria.
- **find_real_targets.py**: Filters the database for targets that are confirmed spendable and have sufficient signature data.
- **find_spending_tx.py**: Locates the first spending transaction for a list of addresses to facilitate public key recovery.
- **import_to_db.py**: Imports external signature and address data from CSV or JSON files into the SQLite database.
- **known_vuln_scanner.py**: Scans for historically documented Bitcoin vulnerabilities and weak key patterns.
- **massive_brainwallet.py**: High-performance multi-threaded brainwallet dictionary scanner using optimized hashing.
- **nuke_targets.py**: Administrative utility for removing specific addresses or corrupted data from the database.
- **raw_block_parser.py**: Low-level parser for raw Bitcoin block files (`blk*.dat`) to extract transaction data.
- **replenish_targets.py**: Surgical fetching service for replenishing the target list with high-value dormant addresses.
- **report_db.py**: Generates a comprehensive summary report of all vulnerabilities and recovered keys in the database.
- **scan_r_reuse.py**: Scans for simple R-reuse (nonce reuse) across an address's transaction history.
- **search_nonce_delta_global.py**: Performs a system-wide search for fixed-delta relationships between all nonces in the database.
- **test_glob.py**: Simple utility for testing file-matching glob patterns.
- **test_lsb_fix.py**: Verification script for confirming the effectiveness of LSB bias detection and fix logic.
