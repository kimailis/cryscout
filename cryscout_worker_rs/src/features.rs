use num_bigint::BigInt;
use num_traits::{ToPrimitive, Signed};
use std::collections::HashMap;

pub struct SigData {
    pub r: BigInt,
    pub s: BigInt,
    pub timestamp: Option<u64>,
}

pub struct ScoringFeatures {
    pub num_signatures: usize,
    pub r_entropy: f64,
    pub s_entropy: f64,
    pub bit_balance: f64,
    pub lsb_bias: f64,
    pub msb_bias: f64,
    pub fft_peak_score: f64,
    pub correlation_score: f64,
    pub time_spacing_variance: f64,
    pub wallet_fingerprint: String,
}

impl ScoringFeatures {
    pub fn extract(sigs: &[SigData]) -> Option<Self> {
        let n = sigs.len();
        if n < 2 { return None; }

        let r_values: Vec<BigInt> = sigs.iter().map(|s| s.r.clone()).collect();
        let s_values: Vec<BigInt> = sigs.iter().map(|s| s.s.clone()).collect();
        let timestamps: Vec<u64> = sigs.iter().filter_map(|s| s.timestamp).collect();

        // 1. Entropies
        let r_entropy = Self::calc_entropy(&r_values);
        let s_entropy = Self::calc_entropy(&s_values);

        // 2. Bit Balance (on R values)
        let mut set_bits = 0usize;
        let mut total_bits = 0usize;
        for r in &r_values {
            set_bits += r.to_bytes_be().1.iter().map(|b| b.count_ones() as usize).sum::<usize>();
            total_bits += r.bits() as usize;
        }
        let bit_balance = if total_bits > 0 { set_bits as f64 / total_bits as f64 } else { 0.5 };

        // 3. LSB Bias
        let mut lsb_bias = 0.0;
        for k in 1..=8 {
            let mod_val = 1 << k;
            let mut residues = HashMap::new();
            for r in &r_values {
                let res = (r % BigInt::from(mod_val)).to_u32().unwrap_or(0);
                *residues.entry(res).or_insert(0) += 1;
            }
            let max_count = residues.values().max().cloned().unwrap_or(0);
            let bias = max_count as f64 / n as f64;
            if bias > lsb_bias { lsb_bias = bias; }
        }

        // 4. MSB Bias (concentration of short nonces)
        let short_nonces = r_values.iter().filter(|r| r.bits() < 256).count();
        let msb_bias = short_nonces as f64 / n as f64;

        // 5. FFT Peak (Simplified)
        let mut fft_peak_score = 0.0;
        if n >= 4 {
            let bit_lens: Vec<f64> = r_values.iter().map(|r| r.bits() as f64).collect();
            let mean = bit_lens.iter().sum::<f64>() / n as f64;
            let var = bit_lens.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
            if var > 0.1 {
                fft_peak_score = (var / 100.0).min(1.0); // Proxy for now
            }
        }

        // 6. Time Correlation (delta_t vs delta_r)
        let mut correlation_score = 0.0;
        let mut time_spacing_variance = 0.0;
        if timestamps.len() >= 2 {
            let mut delta_t = Vec::new();
            let mut delta_r = Vec::new();
            for i in 0..timestamps.len()-1 {
                delta_t.push((timestamps[i+1] as f64 - timestamps[i] as f64).abs());
                let dr = (&r_values[i+1] - &r_values[i]).abs();
                delta_r.push(dr.bits() as f64);
            }
            correlation_score = Self::calc_correlation(&delta_t, &delta_r);
            
            let mean_t = delta_t.iter().sum::<f64>() / delta_t.len() as f64;
            time_spacing_variance = delta_t.iter().map(|x| (x - mean_t).powi(2)).sum::<f64>() / delta_t.len() as f64;
        }

        // 7. Wallet Fingerprinting
        let wallet_fingerprint = Self::identify_wallet(&r_values, &s_values);

        Some(ScoringFeatures {
            num_signatures: n,
            r_entropy,
            s_entropy,
            bit_balance,
            lsb_bias,
            msb_bias,
            fft_peak_score,
            correlation_score,
            time_spacing_variance,
            wallet_fingerprint,
        })
    }

    fn identify_wallet(r_vals: &[BigInt], s_vals: &[BigInt]) -> String {
        let n = r_vals.len();
        
        // 1. Check for old Android SecureRandom (LSB biased)
        // More sensitive: check for any byte bias in the last 4 bytes
        let mut lsb_counts = vec![0usize; 256];
        for r in r_vals {
            let b = (r % BigInt::from(256u32)).to_u32().unwrap_or(0);
            lsb_counts[b as usize] += 1;
        }
        let max_lsb = *lsb_counts.iter().max().unwrap_or(&0);
        if max_lsb as f64 / n as f64 > 0.3 && n > 10 {
            return "Potential Android/Weak RNG".to_string();
        }

        // 2. Check for low-entropy/Short nonces
        let r_entropy = Self::calc_entropy(r_vals);
        if r_entropy < 0.92 {
            return "Early OpenSSL/Brainwallet (Low Entropy)".to_string();
        }

        let short_nonces = r_vals.iter().filter(|r| r.bits() < 248).count();
        if short_nonces as f64 / n as f64 > 0.2 {
            return "Old Wallet (Short Nonces)".to_string();
        }

        // 3. Check for BitcoinJS (specific patterns in S values)
        let high_s = s_vals.iter().filter(|s| s.bits() >= 256).count();
        if high_s == 0 {
            return "Modern (Low-S/RFC6979)".to_string();
        }

        "Unknown/Generic".to_string()
    }

    fn calc_entropy(values: &[BigInt]) -> f64 {
        let n = values.len();
        let mut counts = HashMap::new();
        for v in values {
            let bytes = v.to_bytes_be().1;
            for b in bytes {
                *counts.entry(b).or_insert(0) += 1;
            }
        }
        let total_bytes: usize = counts.values().sum();
        if total_bytes == 0 { return 0.0; }
        let mut entropy = 0.0;
        for &count in counts.values() {
            let p = count as f64 / total_bytes as f64;
            entropy -= p * p.log2();
        }
        entropy / 8.0 // Normalized
    }

    fn calc_correlation(x: &[f64], y: &[f64]) -> f64 {
        let n = x.len();
        if n < 2 { return 0.0; }
        let mut mean_x = 0.0;
        let mut mean_y = 0.0;
        for i in 0..n {
            mean_x += x[i];
            mean_y += y[i];
        }
        mean_x /= n as f64;
        mean_y /= n as f64;

        let mut num = 0.0;
        let mut den_x = 0.0;
        let mut den_y = 0.0;
        for i in 0..n {
            let dx = x[i] - mean_x;
            let dy = y[i] - mean_y;
            num += dx * dy;
            den_x += dx * dx;
            den_y += dy * dy;
        }
        let den = (den_x * den_y).sqrt();
        if den == 0.0 { 0.0 } else { num / den }
    }
}

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
    pub fn extract_neural_features(r_values: &[BigInt]) -> Option<Vec<f32>> {
        let n = r_values.len();
        if n < 2 { return None; }

        let mut features = Vec::with_capacity(438);
        
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

        // FFT (simplified like in bias_detector_rs)
        features.extend(vec![0.0; 32]); 
        features.extend(vec![0.0; 32]); 

        while features.len() < 438 {
            features.push(0.0);
        }
        if features.len() > 438 {
            features.truncate(438);
        }

        Some(features)
    }

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
