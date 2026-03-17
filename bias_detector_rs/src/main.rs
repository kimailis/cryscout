use anyhow::{anyhow, Result};
use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::{Num, Zero, ToPrimitive};
use rusqlite::{params, Connection};
use rustfft::{FftPlanner, num_complex::Complex as FftComplex};
use serde::Deserialize;
use std::collections::HashMap;
use ort::{inputs, Session, SessionBuilder, Value};
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

    if r_values.len() < 2 {
        log("Not enough signatures for analysis.");
        return Ok(());
    }

    if Path::new(FFNN_MODEL_PATH).exists() {
        log("Running Neural Anomaly Detector (FFNN)...");
        if let Some(feats) = NonceFeatures::extract(&r_values) {
            let session = Session::builder()?.commit_from_file(FFNN_MODEL_PATH)?;
            let input_tensor = Array2::from_shape_vec((1, FEATURE_DIM), feats)?;
            let outputs = session.run(inputs![input_tensor]?)?;
            let output_tensor = outputs["output"].try_extract_tensor::<f32>()?;
            let prob = output_tensor[[0, 0]];
            
            log(&format!("  FFNN P(vulnerable): {:.4}", prob));
            if prob > 0.8 {
                log("  [!!!] HIGH ANOMALY DETECTED by Neural Network.");
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
