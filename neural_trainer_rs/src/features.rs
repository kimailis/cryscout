//! Feature extraction for signature analysis.
//!
//! Extracts the same 438-dimension feature vector used by the production scorer,
//! plus additional meta-features useful for the learning model.

use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero, One};
use std::collections::HashMap;
use std::f64::consts::PI;

/// Extract the 438-dim feature vector from R values (same as cryscout_worker_rs).
pub fn extract_438_features(r_values: &[BigInt]) -> Option<Vec<f32>> {
    let n = r_values.len();
    if n < 2 { return None; }

    let mut features = Vec::with_capacity(438);

    // Convert R values to 32-byte big-endian
    let mut r_bytes: Vec<Vec<u8>> = Vec::with_capacity(n);
    for r in r_values {
        let mut b = r.to_bytes_be().1;
        if b.len() < 32 {
            let mut padded = vec![0u8; 32 - b.len()];
            padded.extend(b);
            b = padded;
        } else if b.len() > 32 {
            b = b[b.len() - 32..].to_vec();
        }
        r_bytes.push(b);
    }

    // [0..256] Per-bit probability (should be ~0.5 for random nonces)
    let mut bit_counts = vec![0u32; 256];
    for b in &r_bytes {
        for i in 0..32 {
            for j in 0..8 {
                if (b[i] >> (7 - j)) & 1 == 1 {
                    bit_counts[i * 8 + j] += 1;
                }
            }
        }
    }
    for count in &bit_counts {
        features.push(*count as f32 / n as f32);
    }

    // [256..288] Per-byte entropy normalized to [0,1]
    for i in 0..32 {
        let mut counts = [0u32; 256];
        for b in &r_bytes {
            counts[b[i] as usize] += 1;
        }
        features.push(normalized_entropy(&counts, n));
    }

    // [288..304] LSB residue max-concentration for 2^1..2^16
    for k in 1..=16 {
        let mod_val: u64 = 1 << k;
        let mut residues = HashMap::new();
        for r in r_values {
            let res = (r % BigInt::from(mod_val)).to_u32().unwrap_or(0);
            *residues.entry(res).or_insert(0u32) += 1;
        }
        let max_count = residues.values().max().cloned().unwrap_or(0);
        features.push(max_count as f32 / n as f32);
    }

    // [304..320] MSB bit-length histogram for bits 241..256
    let bit_lengths: Vec<usize> = r_values.iter().map(|r| r.bits() as usize).collect();
    for target_bl in 241..=256 {
        let count = bit_lengths.iter().filter(|&&bl| bl == target_bl).count();
        features.push(count as f32 / n as f32);
    }

    // [320..352] Inter-sig delta bit-length histogram
    let mut sorted_r = r_values.to_vec();
    sorted_r.sort();
    let deltas: Vec<BigInt> = (0..n - 1).map(|i| &sorted_r[i + 1] - &sorted_r[i]).collect();
    if !deltas.is_empty() {
        for target in 224..256 {
            let count = deltas.iter().filter(|d| d.bits() as usize == target).count();
            features.push(count as f32 / deltas.len() as f32);
        }
    } else {
        features.extend(vec![0.0f32; 32]);
    }

    // [352..358] Chi-squared mod small primes
    for prime in &[2u64, 3, 5, 7, 11, 13] {
        let mut counts = vec![0u32; *prime as usize];
        for r in r_values {
            let res = (r % BigInt::from(*prime)).to_usize().unwrap_or(0);
            counts[res] += 1;
        }
        let expected = n as f32 / *prime as f32;
        let chi2: f32 = counts.iter().map(|&c| (c as f32 - expected).powi(2) / expected).sum();
        features.push((chi2 / 100.0).min(1.0));
    }

    // [358..374] Autocorrelation lags 1..16
    let r_floats: Vec<f64> = r_values.iter().map(|r| {
        let mask = BigInt::one() << 53;
        let val: BigInt = r % &mask;
        val.to_f64().unwrap_or(0.0)
    }).collect();
    let mean = r_floats.iter().sum::<f64>() / n as f64;
    let var = r_floats.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;

    for lag in 1..=16 {
        if lag < n && var > 0.0 {
            let mut cov = 0.0;
            for i in 0..n - lag {
                cov += (r_floats[i] - mean) * (r_floats[i + lag] - mean);
            }
            let corr = (cov / (n as f64 * var)) as f32;
            features.push(if corr.is_nan() { 0.0 } else { corr });
        } else {
            features.push(0.0);
        }
    }

    // [374..406] FFT magnitude spectrum (32 bins)
    let spectral_input: Vec<f64> = r_bytes.iter().map(|b| {
        let mut acc = 0u64;
        for byte in b.iter().take(8) {
            acc = (acc << 8) | (*byte as u64);
        }
        acc as f64
    }).collect();
    if !spectral_input.is_empty() {
        let smean = spectral_input.iter().sum::<f64>() / spectral_input.len() as f64;
        let centered: Vec<f64> = spectral_input.iter().map(|v| v - smean).collect();
        for k in 0..32 {
            if k < centered.len() {
                let mut real = 0.0;
                let mut imag = 0.0;
                for (idx, value) in centered.iter().enumerate() {
                    let angle = 2.0 * PI * (k as f64) * (idx as f64) / centered.len() as f64;
                    real += value * angle.cos();
                    imag -= value * angle.sin();
                }
                let magnitude = (real * real + imag * imag).sqrt();
                let normalized = (magnitude / centered.len() as f64).ln_1p() / 32.0;
                features.push(normalized.min(1.0) as f32);
            } else {
                features.push(0.0);
            }
        }
    } else {
        features.extend(vec![0.0f32; 32]);
    }

    // [406..438] Reverse (LSB-side) byte entropy
    for i in 0..32 {
        let mut counts = [0u32; 256];
        for b in &r_bytes {
            counts[b[31 - i] as usize] += 1;
        }
        features.push(normalized_entropy(&counts, n));
    }

    // Pad/truncate to exactly 438
    while features.len() < 438 {
        features.push(0.0);
    }
    features.truncate(438);

    Some(features)
}

fn normalized_entropy(counts: &[u32], total: usize) -> f32 {
    let mut entropy = 0.0f32;
    for &count in counts {
        if count > 0 {
            let p = count as f32 / total as f32;
            entropy -= p * p.log2();
        }
    }
    entropy / 8.0
}

/// Extended feature extraction: additional meta-features beyond the 438.
/// These capture higher-level structural patterns.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExtendedFeatures {
    /// The standard 438-dim vector
    pub base: Vec<f32>,
    /// Number of signatures
    pub num_sigs: usize,

    // --- Derived summary features ---
    /// Mean bit probability deviation from 0.5
    pub mean_bit_deviation: f64,
    /// Max bit probability deviation from 0.5
    pub max_bit_deviation: f64,
    /// Number of bits with > 2-sigma deviation from 0.5
    pub num_biased_bits: usize,
    /// Mean byte entropy (should be ~1.0 for random)
    pub mean_byte_entropy: f64,
    /// Min byte entropy
    pub min_byte_entropy: f64,
    /// Fraction of R values with bit length < 256 (MSB bias indicator)
    pub short_r_fraction: f64,
    /// Mean R bit length
    pub mean_r_bit_length: f64,
    /// Max autocorrelation (absolute) across lags 1-16
    pub max_autocorrelation: f64,
    /// Max FFT magnitude
    pub max_fft_magnitude: f64,
    /// Whether any two R values are identical (nonce reuse)
    pub has_r_reuse: bool,
    /// Min delta between sorted R values (in bits)
    pub min_delta_bits: u64,
    /// Fraction of LSB residues that are biased (exceed expected + 3 sigma)
    pub lsb_bias_fraction: f64,
}

impl ExtendedFeatures {
    pub fn extract(r_values: &[BigInt]) -> Option<Self> {
        let base = extract_438_features(r_values)?;
        let n = r_values.len();

        // Bit deviations (features 0..256)
        let bit_devs: Vec<f64> = base[0..256].iter()
            .map(|&p| (p as f64 - 0.5).abs())
            .collect();
        let mean_bit_deviation = bit_devs.iter().sum::<f64>() / 256.0;
        let max_bit_deviation = bit_devs.iter().cloned().fold(0.0f64, f64::max);
        let sigma = 0.5 / (n as f64).sqrt();
        let num_biased_bits = bit_devs.iter().filter(|&&d| d > 2.0 * sigma).count();

        // Byte entropy (features 256..288)
        let byte_ents: Vec<f64> = base[256..288].iter().map(|&e| e as f64).collect();
        let mean_byte_entropy = byte_ents.iter().sum::<f64>() / 32.0;
        let min_byte_entropy = byte_ents.iter().cloned().fold(1.0f64, f64::min);

        // MSB bias (features 304..320)
        let short_r_fraction: f64 = base[304..319].iter().map(|&f| f as f64).sum();
        let mean_r_bit_length = {
            let bls: Vec<f64> = r_values.iter().map(|r| r.bits() as f64).collect();
            bls.iter().sum::<f64>() / n as f64
        };

        // Autocorrelation (features 358..374)
        let max_autocorrelation = base[358..374].iter()
            .map(|&a| (a as f64).abs())
            .fold(0.0f64, f64::max);

        // FFT magnitude (features 374..406)
        let max_fft_magnitude = base[374..406].iter()
            .map(|&f| f as f64)
            .fold(0.0f64, f64::max);

        // R reuse detection
        let mut r_set: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        let mut has_r_reuse = false;
        for r in r_values {
            let rb = r.to_bytes_be().1;
            if !r_set.insert(rb) {
                has_r_reuse = true;
                break;
            }
        }

        // Min delta between sorted R values
        let mut sorted_r = r_values.to_vec();
        sorted_r.sort();
        let min_delta_bits = if n > 1 {
            (0..n - 1)
                .map(|i| (&sorted_r[i + 1] - &sorted_r[i]).bits())
                .min()
                .unwrap_or(256)
        } else {
            256
        };

        // LSB bias
        let lsb_bias_count = (0..16usize).filter(|&k| {
            let observed = base[288 + k] as f64;
            let expected = 1.0 / (1 << (k + 1)) as f64;
            let noise = (expected / n as f64).sqrt();
            observed > expected + 3.0 * noise
        }).count();
        let lsb_bias_fraction = lsb_bias_count as f64 / 16.0;

        Some(ExtendedFeatures {
            base,
            num_sigs: n,
            mean_bit_deviation,
            max_bit_deviation,
            num_biased_bits,
            mean_byte_entropy,
            min_byte_entropy,
            short_r_fraction,
            mean_r_bit_length,
            max_autocorrelation,
            max_fft_magnitude,
            has_r_reuse,
            min_delta_bits,
            lsb_bias_fraction,
        })
    }

    /// Compact summary vector for the learning model (13 meta-features)
    pub fn summary_vector(&self) -> Vec<f64> {
        vec![
            self.num_sigs as f64,
            self.mean_bit_deviation,
            self.max_bit_deviation,
            self.num_biased_bits as f64,
            self.mean_byte_entropy,
            self.min_byte_entropy,
            self.short_r_fraction,
            self.mean_r_bit_length,
            self.max_autocorrelation,
            self.max_fft_magnitude,
            if self.has_r_reuse { 1.0 } else { 0.0 },
            self.min_delta_bits as f64,
            self.lsb_bias_fraction,
        ]
    }
}
