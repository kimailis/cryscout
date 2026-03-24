use anyhow::{Result};
use num_bigint::{BigInt};

use num_traits::{Num, Zero, ToPrimitive};
use rusqlite::{params, Connection};
use rustfft::{FftPlanner, num_complex::Complex as FftComplex};
use serde::Deserialize;
use std::collections::HashMap;
use ort::{inputs, Session};
use ndarray::{Array2, Axis};
use std::path::Path;
use chrono::Local;

const P_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const DB_FILE: &str = "cryscout.db";
const FEATURE_DIM: usize = 438;
const FFNN_MODEL_PATH: &str = "nonce_anomaly_model.onnx";
const LSTM_MODEL_PATH: &str = "spectral_bias_lstm.onnx";

#[derive(Deserialize, Debug)]
struct SigDb {
    r_hex: String,
    s_hex: String,
    z_hex: String,
}

pub struct NonceFeatures;

impl NonceFeatures {
    pub fn extract(r_values: &[BigInt]) -> Option<Vec<f32>> {
        let n = r_values.len();
        if n < 2 { return None; }

        let mut features = Vec::with_capacity(FEATURE_DIM);
        
        let mut r_bytes = Vec::with_capacity(n);
        for r in r_values {
            let mut b = r.to_bytes_be().1;
            if b.len() < 32 {
                let mut padded = vec![0u8; 32 - b.len()];
                padded.extend(b);
                b = padded;
            } else if b.len() > 32 {
                b = b[b.len()-32..].to_vec();
            }
            r_bytes.push(b);
        }

        let mut bit_counts = vec![0u32; 256];
        for b in &r_bytes {
            for i in 0..32 {
                for j in 0..8 {
                    if (b[i] >> (7-j)) & 1 == 1 {
                        bit_counts[i*8 + j] += 1;
                    }
                }
            }
        }
        for count in bit_counts {
            features.push(count as f32 / n as f32);
        }

        for i in 0..32 {
            let mut counts = [0u32; 256];
            for b in &r_bytes {
                counts[b[i] as usize] += 1;
            }
            let mut entropy = 0.0;
            for count in counts {
                if count > 0 {
                    let p = count as f32 / n as f32;
                    entropy -= p * p.log2();
                }
            }
            features.push(entropy / 8.0);
        }

        for k in 1..=16 {
            let mod_val = 1 << k;
            let mut residues = HashMap::new();
            for r in r_values {
                let res = (r % BigInt::from(mod_val)).to_u32().unwrap_or(0);
                *residues.entry(res).or_insert(0) += 1;
            }
            let max_count = residues.values().max().cloned().unwrap_or(0);
            features.push(max_count as f32 / n as f32);
        }

        let mut bit_lengths = vec![0usize; n];
        for (idx, r) in r_values.iter().enumerate() {
            bit_lengths[idx] = r.bits() as usize;
        }
        for target_bl in 241..=256 {
            let count = bit_lengths.iter().filter(|&&bl| bl == target_bl).count();
            features.push(count as f32 / n as f32);
        }

        let mut sorted_r = r_values.to_vec();
        sorted_r.sort();
        let mut deltas = Vec::new();
        for i in 0..n-1 {
            deltas.push(&sorted_r[i+1] - &sorted_r[i]);
        }
        if !deltas.is_empty() {
            for target in 224..256 {
                let count = deltas.iter().filter(|d| d.bits() as usize == target).count();
                features.push(count as f32 / deltas.len() as f32);
            }
        } else {
            features.extend(vec![0.0; 32]);
        }

        for prime in &[2, 3, 5, 7, 11, 13] {
            let mut counts = vec![0u32; *prime];
            for r in r_values {
                let res = (r % BigInt::from(*prime)).to_usize().unwrap_or(0);
                counts[res] += 1;
            }
            let expected = n as f32 / *prime as f32;
            let chi2: f32 = counts.iter().map(|&c| (c as f32 - expected).powi(2) / expected).sum();
            features.push((chi2 / 100.0).min(1.0));
        }

        let r_floats: Vec<f64> = r_values.iter().map(|r| {
            let mask = BigInt::from(1u64) << 53;
            let val: BigInt = r % &mask;
            val.to_f64().unwrap_or(0.0)
        }).collect();
        let mean = r_floats.iter().sum::<f64>() / n as f64;
        let var = r_floats.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        
        for lag in 1..=16 {
            if lag < n && var > 0.0 {
                let mut cov = 0.0;
                for i in 0..n-lag {
                    cov += (r_floats[i] - mean) * (r_floats[i+lag] - mean);
                }
                let corr = (cov / (n as f64 * var)) as f32;
                features.push(if corr.is_nan() { 0.0 } else { corr });
            } else {
                features.push(0.0);
            }
        }

        if n >= 4 {
             let mut planner = FftPlanner::new();
             let fft_size = (n as f64).log2().ceil().exp2() as usize;
             let mut samples: Vec<FftComplex<f32>> = vec![FftComplex::new(0.0, 0.0); fft_size];
             for i in 0..n {
                 samples[i].re = r_values[i].bits() as f32;
             }
             let fft = planner.plan_fft_forward(fft_size);
             fft.process(&mut samples);
             for i in 0..32 {
                 if i < samples.len() {
                     features.push((samples[i].norm() / n as f32 / 10.0).min(1.0));
                 } else {
                     features.push(0.0);
                 }
             }
        } else {
            features.extend(vec![0.0; 32]);
        }

        features.extend(vec![0.0; 32]);

        while features.len() < FEATURE_DIM {
            features.push(0.0);
        }
        if features.len() > FEATURE_DIM {
            features.truncate(FEATURE_DIM);
        }

        Some(features)
    }

    pub fn extract_sequence(r_values: &[BigInt], max_len: usize) -> Array2<f32> {
        let mut seq = Array2::zeros((max_len, 64));
        for (i, r) in r_values.iter().take(max_len).enumerate() {
            for j in 0..64 {
                let shifted: BigInt = r >> (j as usize);
                if shifted.get_bit(0) {
                    seq[[i, j]] = 1.0;
                }
            }
        }
        seq
    }
}

trait BigIntExt {
    fn get_bit(&self, bit: usize) -> bool;
}

impl BigIntExt for BigInt {
    fn get_bit(&self, bit: usize) -> bool {
        !(self & (BigInt::from(1u64) << bit)).is_zero()
    }
}

/// Deterministic anomaly scorer — interprets the 438-dim feature vector directly.
/// num_sigs controls sample-size confidence: with few sigs, scores are dampened.
fn deterministic_anomaly_score(feats: &[f32], num_sigs: usize) -> f32 {
    if feats.len() < 438 { return 0.5; }

    let confidence = if num_sigs <= 2 { 0.0 } else {
        1.0 - 1.0 / (1.0 + (num_sigs as f64 - 2.0) / 25.0)
    };

    let mut score = 0.0f64;
    let mut weight_sum = 0.0f64;

    // 1. Bit distribution bias (features 0..256)
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
    {
        let w = 3.5;
        let mut lsb_score = 0.0;
        for k in 0..16usize {
            let observed = feats[288 + k] as f64;
            let expected = 1.0 / (1 << (k + 1)) as f64;
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
    {
        let w = 3.5;
        let short_frac: f64 = feats[304..319].iter().map(|&f| f as f64).sum();
        let msb_score = (short_frac * 3.0).min(1.0);
        score += msb_score * w;
        weight_sum += w;
    }

    // 5. Chi-squared modular residues (features 352..358)
    {
        let w = 2.5;
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
    {
        let w = 2.5;
        let fft_mags: Vec<f64> = feats[374..406].iter().map(|&f| f as f64).collect();
        let mean_fft = fft_mags.iter().sum::<f64>() / 32.0;
        let max_fft = fft_mags.iter().cloned().fold(0.0f64, f64::max);
        let peak_ratio = if mean_fft > 1e-9 { max_fft / mean_fft } else { 0.0 };
        let fft_score = ((peak_ratio - 1.0).max(0.0) / 10.0 + max_fft * 3.0).min(1.0);
        score += fft_score * w;
        weight_sum += w;
    }

    // 8. Reverse (LSB-side) entropy (features 406..438)
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

    let raw_prob = if weight_sum > 0.0 { score / weight_sum } else { 0.0 };
    let adjusted = 0.5 + (raw_prob - 0.5) * confidence;
    let k = 8.0;
    let midpoint = 0.3;
    let sharpened = 1.0 / (1.0 + (-k * (adjusted - midpoint)).exp());
    sharpened as f32
}

fn log(msg: &str) {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S");
    println!("[{}] {}", now, msg);
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <address>", args[0]);
        return Ok(());
    }

    let address = &args[1];
    let conn = Connection::open(DB_FILE)?;
    let _ = conn.pragma_update(None, "busy_timeout", &30000);
    
    log(&format!("Loading signatures for address: {}", address));
    let mut stmt = conn.prepare("SELECT r_int, r_hex, s_hex, z_hex FROM signatures WHERE address = ?1")?;
    
    let rows = stmt.query_map(params![address], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?
        ))
    })?;

    let mut r_values = Vec::new();
    for row_res in rows {
        let (r_int, r_hex, _, _) = row_res?;
        let r = BigInt::from_str_radix(&r_int, 10).unwrap_or_else(|_| BigInt::from_str_radix(&r_hex, 16).unwrap_or_default());
        r_values.push(r);
    }

    if r_values.len() < 5 {
        log(&format!("Not enough signatures for analysis ({}, need ≥5).", r_values.len()));
        return Ok(());
    }

    log("Running Statistical Anomaly Detector (Deterministic)...");
    if let Some(feats) = NonceFeatures::extract(&r_values) {
        let det_score = deterministic_anomaly_score(&feats, r_values.len());
        log(&format!("  Deterministic P(vulnerable): {:.4}", det_score));

        if det_score > 0.7 {
            let severity = if det_score > 0.9 { "CRITICAL" } else { "HIGH" };
            log(&format!("  [!!!] {} ANOMALY DETECTED — nonce generation is non-random.", severity));
        } else if det_score > 0.5 {
            log("  [~] Moderate anomaly signal — borderline, needs more signatures.");
        } else {
            log("  [-] No significant anomaly detected.");
        }

        // Also run ONNX if available, for comparison
        if Path::new(FFNN_MODEL_PATH).exists() {
            log("Running ONNX Neural Anomaly Detector (secondary)...");
            let session = Session::builder()?.commit_from_file(FFNN_MODEL_PATH)?;
            let input_tensor = Array2::from_shape_vec((1, FEATURE_DIM), feats)?;
            let outputs = session.run(inputs![input_tensor]?)?;
            let output_tensor = outputs["output"].try_extract_tensor::<f32>()?;
            let prob = output_tensor[[0, 0]];
            log(&format!("  ONNX P(vulnerable): {:.4}", prob));
            if (prob - 0.5).abs() < 0.05 {
                log("  [!] ONNX model appears uncalibrated (output stuck near 0.5). Relying on deterministic scorer.");
            }
        }
    }

    if Path::new(LSTM_MODEL_PATH).exists() && r_values.len() >= 20 {
        log("Running Spectral Bias Predictor (LSTM)...");
        let session = Session::builder()?.commit_from_file(LSTM_MODEL_PATH)?;
        let seq = NonceFeatures::extract_sequence(&r_values, 20);
        let input_tensor = seq.insert_axis(Axis(0));
        
        let outputs = session.run(inputs![input_tensor]?)?;
        let output_tensor = outputs["output"].try_extract_tensor::<f32>()?;
        
        let mut confidence = 0.0;
        for i in 0..64 {
            let p = output_tensor[[0, i]];
            confidence += (p - 0.5).abs() * 2.0;
        }
        let avg_confidence = confidence / 64.0;
        log(&format!("  LSTM Predictability Score: {:.4}", avg_confidence));
        if avg_confidence > 0.7 {
            log("  [!!!] HIGH SPECTRAL PREDICTABILITY DETECTED.");
        }
    }

    Ok(())
}
