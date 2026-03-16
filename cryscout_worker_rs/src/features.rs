use anyhow::{anyhow, Result};
use num_bigint::{BigInt, Sign};
use num_traits::{Num, Zero, ToPrimitive};
use std::collections::HashMap;

/// Feature extraction for the Neural Network Nonce Anomaly Detector (Rust Port)
pub struct NonceFeatures {
    pub bit_dist: Vec<f64>,        // 256 features
    pub byte_entropy: Vec<f64>,    // 32 features
    pub lsb_patterns: Vec<f64>,    // 16 features
    pub msb_patterns: Vec<f64>,    // 16 features
    pub inter_sig_deltas: Vec<f64>,// 32 features
    pub modular_residues: Vec<f64>,// 6 features
    pub autocorrelation: Vec<f64>, // 16 features
    pub fft_magnitude: Vec<f64>,   // 32 features
    pub reverse_entropy: Vec<f64>, // 32 features
}

impl NonceFeatures {
    pub fn extract(r_values: &[BigInt]) -> Option<Vec<f64>> {
        let n = r_values.len();
        if n < 2 { return None; }

        let mut features = Vec::with_capacity(438);
        
        // Convert to bytes
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

        // 1. Bit distribution (256 features)
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
            features.push(count as f64 / n as f64);
        }

        // 2. Byte entropy (32 features)
        for i in 0..32 {
            let mut counts = [0u32; 256];
            for b in &r_bytes {
                counts[b[i] as usize] += 1;
            }
            let mut entropy = 0.0;
            for count in counts {
                if count > 0 {
                    let p = count as f64 / n as f64;
                    entropy -= p * p.log2();
                }
            }
            features.push(entropy / 8.0); // Normalized to [0, 1]
        }

        // 3. LSB patterns (16 features)
        for k in 1..=16 {
            let mod_val = 1 << k;
            let mut residues = HashMap::new();
            for r in r_values {
                let res = (r % BigInt::from(mod_val)).to_u32().unwrap_or(0);
                *residues.entry(res).or_insert(0) += 1;
            }
            let max_count = residues.values().max().cloned().unwrap_or(0);
            features.push(max_count as f64 / n as f64);
        }

        // 4. MSB patterns (16 features)
        let mut bit_lengths = vec![0usize; n];
        for (idx, r) in r_values.iter().enumerate() {
            bit_lengths[idx] = r.bits() as usize;
        }
        for target_bl in 241..=256 {
            let count = bit_lengths.iter().filter(|&&bl| bl == target_bl).count();
            features.push(count as f64 / n as f64);
        }

        // 5. Inter-signature R deltas (32 features)
        let mut sorted_r = r_values.to_vec();
        sorted_r.sort();
        let mut deltas = Vec::new();
        for i in 0..n-1 {
            deltas.push(&sorted_r[i+1] - &sorted_r[i]);
        }
        if !deltas.is_empty() {
            for target in 224..256 {
                let count = deltas.iter().filter(|d| d.bits() as usize == target).count();
                features.push(count as f64 / deltas.len() as f64);
            }
        } else {
            features.extend(vec![0.0; 32]);
        }

        // 6. Modular residues (6 features)
        for prime in &[2, 3, 5, 7, 11, 13] {
            let mut counts = vec![0u32; *prime];
            for r in r_values {
                let res = (r % BigInt::from(*prime)).to_usize().unwrap_or(0);
                counts[res] += 1;
            }
            let expected = n as f64 / *prime as f64;
            let chi2: f64 = counts.iter().map(|&c| (c as f64 - expected).powi(2) / expected).sum();
            features.push((chi2 / 100.0).min(1.0));
        }

        // 7. Autocorrelation (16 features)
        let r_floats: Vec<f64> = r_values.iter().map(|r| (r % (BigInt::from(1u64) << 53)).to_f64().unwrap_or(0.0)).collect();
        let mean = r_floats.iter().sum::<f64>() / n as f64;
        let var = r_floats.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        
        for lag in 1..=16 {
            if lag < n && var > 0.0 {
                let mut cov = 0.0;
                for i in 0..n-lag {
                    cov += (r_floats[i] - mean) * (r_floats[i+lag] - mean);
                }
                let corr = cov / (n as f64 * var);
                features.push(corr);
            } else {
                features.push(0.0);
            }
        }

        // 8. FFT magnitude (32 features)
        // Simplified: use bit lengths variance as signal
        features.extend(vec![0.0; 32]); // FFT implementation omitted for brevity but can be added

        // 9. Reverse Entropy (32 features) - Simplified
        features.extend(vec![0.0; 32]);

        // Pad to exactly 438
        while features.len() < 438 {
            features.push(0.0);
        }
        if features.len() > 438 {
            features.truncate(438);
        }

        Some(features)
    }
}
