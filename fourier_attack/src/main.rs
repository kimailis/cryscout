use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet};
use std::fs::File;
use std::io::BufReader;
use rayon::prelude::*;
use serde_json::Value;
use std::f64::consts::PI;

#[derive(Serialize, Deserialize, Debug)]
struct Signature {
    r: Value,
    s: Value,
    z: Value,
}

#[derive(Clone, Debug)]
struct Sig {
    u: BigInt,
    t: BigInt,
}

fn value_to_bigint(v: &Value) -> Option<BigInt> {
    match v {
        Value::Number(n) => BigInt::parse_bytes(n.to_string().as_bytes(), 10),
        Value::String(s) => BigInt::parse_bytes(s.as_bytes(), 10),
        _ => None,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        println!("Usage: fourier_attack <sigs.json> <address>");
        return;
    }

    let file_path = &args[1];
    let n_big = BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16).unwrap();
    let n_f64 = 1.15792089237316195423570985008687907853269984665640564039457584007913129639936e77f64; // Approx

    println!("[*] Loading signatures...");
    let file = File::open(file_path).expect("Failed to open file");
    let reader = BufReader::new(file);
    let sigs_json: Vec<Signature> = serde_json::from_reader(reader).expect("Failed to parse JSON");

    let mut unique_sigs = Vec::new();
    let mut seen = HashSet::new();
    for s in sigs_json {
        if let (Some(r), Some(s_val), Some(z)) = (value_to_bigint(&s.r), value_to_bigint(&s.s), value_to_bigint(&s.z)) {
            if seen.insert((r.clone(), s_val.clone())) {
                let s_inv = s_val.modpow(&(&n_big - 2u32), &n_big);
                unique_sigs.push(Sig {
                    u: (&s_inv * &z) % &n_big,
                    t: (&s_inv * &r) % &n_big,
                });
            }
        }
    }
    println!("[*] Using {} unique signatures.", unique_sigs.len());

    // Pre-calculate floats for speed
    let sig_data: Vec<(f64, f64)> = unique_sigs.iter().map(|s| {
        let t_f = bigint_to_f64(&s.t, &n_big);
        let u_f = bigint_to_f64(&s.u, &n_big);
        (t_f, u_f)
    }).collect();

    println!("[*] Scanning d in range [0, 2^24]...");
    
    let chunk_size = 10000;
    let max_d = 1 << 24;
    
    let all_bests: Vec<(f64, usize)> = (0..max_d).into_par_iter().step_by(chunk_size).map(|start| {
        let mut local_best_score = 0.0;
        let mut local_best_d = 0;
        
        for d in start..std::cmp::min(start + chunk_size, max_d) {
            let mut sum_re = 0.0;
            let mut sum_im = 0.0;
            
            for (t_f, u_f) in &sig_data {
                let theta = 2.0 * PI * ((*t_f * d as f64) + *u_f);
                sum_re += theta.cos();
                sum_im += theta.sin();
            }
            
            let score = (sum_re * sum_re + sum_im * sum_im).sqrt();
            if score > local_best_score {
                local_best_score = score;
                local_best_d = d;
            }
        }
        (local_best_score, local_best_d)
    }).collect();

    let mut sorted_bests = all_bests;
    sorted_bests.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());

    println!("\n[*] Scan complete. Top 5 candidates:");
    for (score, d) in sorted_bests.iter().take(5) {
        println!("  d = {} | Score: {:.2} (expected random: {:.2})", d, score, (sig_data.len() as f64).sqrt());
    }
    
    let best = sorted_bests[0];
    if best.0 > (sig_data.len() as f64).sqrt() * 3.0 {
        println!("!!! POTENTIAL HIT !!! Best candidate d = {}", best.1);
    }
}

fn bigint_to_f64(b: &BigInt, n: &BigInt) -> f64 {
    // Convert to [0, 1] range
    let (sign, bytes) = b.to_bytes_be();
    let mut val = 0.0;
    let mut weight = 1.0;
    for &byte in bytes.iter() {
        weight /= 256.0;
        val += byte as f64 * weight;
    }
    if sign == Sign::Minus { -val } else { val }
}

trait BigIntExt {
    fn mod_floor(&self, n: &BigInt) -> BigInt;
}

impl BigIntExt for BigInt {
    fn mod_floor(&self, n: &BigInt) -> BigInt {
        let res = self % n;
        if res.sign() == Sign::Minus {
            res + n
        } else {
            res
        }
    }
}
