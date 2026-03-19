
use num_bigint::{BigInt, Sign};

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
    a: BigInt,
    b: BigInt,
}

fn value_to_bigint(v: &Value) -> Option<BigInt> {
    match v {
        Value::Number(n) => BigInt::parse_bytes(n.to_string().as_bytes(), 10),
        Value::String(s) => {
            if s.starts_with("0x") {
                BigInt::parse_bytes(s[2..].as_bytes(), 16)
            } else {
                BigInt::parse_bytes(s.as_bytes(), 10)
            }
        },
        _ => None,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: bleichenbacher_fourier <sigs.json>");
        return;
    }

    let file_path = &args[1];
    let n_big = BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16).unwrap();

    println!("[*] Loading signatures...");
    let file = File::open(file_path).expect("Failed to open file");
    let reader = BufReader::new(file);
    let sigs_json: Vec<Signature> = serde_json::from_reader(reader).expect("Failed to parse JSON");

    let mut sigs = Vec::new();
    let mut seen = HashSet::new();
    for s in sigs_json {
        if let (Some(r), Some(s_val), Some(z)) = (value_to_bigint(&s.r), value_to_bigint(&s.s), value_to_bigint(&s.z)) {
            if seen.insert((r.clone(), s_val.clone())) {
                let s_inv = s_val.modpow(&(&n_big - 2u32), &n_big);
                sigs.push(Sig {
                    a: (&s_inv * &z) % &n_big,
                    b: (&s_inv * &r) % &n_big,
                });
            }
        }
    }
    let n_sigs = sigs.len();
    println!("[*] Loaded {} unique signatures.", n_sigs);

    if n_sigs < 2 {
        println!("[!] Not enough signatures.");
        return;
    }

    println!("[*] Generating 4-list sum combinations (Level 1: Pairs)...");
    // Level 1: Pairs (b_i - b_j, a_i - a_j)
    // To keep it manageable, we only take a subset if n_sigs is large
    let mut pairs = Vec::new();
    for i in 0..n_sigs {
        for j in i + 1..n_sigs {
            let b_diff = (&sigs[i].b - &sigs[j].b).mod_floor(&n_big);
            let a_diff = (&sigs[i].a - &sigs[j].a).mod_floor(&n_big);
            pairs.push(Sig { a: a_diff, b: b_diff });
        }
    }
    println!("[*] Generated {} pairs.", pairs.len());

    println!("[*] Generating 4-list sum combinations (Level 2: Pairs of Pairs)...");
    // Level 2: Pairs of Pairs (b_p1 - b_p2, a_p1 - a_p2)
    // We want the resulting b to be small. 
    // We sort Level 1 by b and take adjacent ones.
    let mut sorted_pairs = pairs;
    sorted_pairs.sort_by(|a, b| a.b.cmp(&b.b));
    
    let mut quads = Vec::new();
    for i in 0..sorted_pairs.len() - 1 {
        let b_diff = (&sorted_pairs[i+1].b - &sorted_pairs[i].b).mod_floor(&n_big);
        // We only care if b_diff is "small"
        if b_diff < (&n_big >> 40) {
            let a_diff = (&sorted_pairs[i+1].a - &sorted_pairs[i].a).mod_floor(&n_big);
            quads.push(Sig { a: a_diff, b: b_diff });
        }
    }
    println!("[*] Generated {} quads with small b (< n/2^40).", quads.len());

    if quads.is_empty() {
        println!("[!] No good combinations found. Falling back to pairs.");
        // Use pairs instead of quads
        quads = sorted_pairs;
    }

    println!("[*] Performing Fourier Search on combinations...");
    // Pre-calculate floats for speed
    let data: Vec<(f64, f64)> = quads.iter().map(|s| {
        (bigint_to_f64(&s.b, &n_big), bigint_to_f64(&s.a, &n_big))
    }).collect();

    let max_d = 1 << 24;
    let chunk_size = 100000;
    
    println!("[*] Scanning d in range [0, 2^24]...");
    let best = (0..max_d).into_par_iter().step_by(chunk_size).map(|start| {
        let mut local_best_score = 0.0;
        let mut local_best_d = 0;
        
        for d in start..std::cmp::min(start + chunk_size, max_d) {
            let mut sum_re = 0.0;
            let mut sum_im = 0.0;
            
            for (b_f, a_f) in &data {
                let theta = 2.0 * PI * ((*b_f * d as f64) + *a_f);
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
    }).max_by(|a, b| a.0.partial_cmp(&b.0).unwrap()).unwrap();

    println!("\n[*] Scan complete.");
    println!("[*] Best candidate d = {} | Score: {:.2} (expected random: {:.2})", best.1, best.0, (data.len() as f64).sqrt());
    
    if best.0 > (data.len() as f64).sqrt() * 5.0 {
        println!("!!! POTENTIAL HIT !!! d = {}", best.1);
    }
}

fn bigint_to_f64(b: &BigInt, _n: &BigInt) -> f64 {
    let (sign, bytes) = b.to_bytes_be();
    let mut val = 0.0;
    let mut weight = 1.0;
    for &byte in bytes.iter().take(8) { // Only take top 64 bits for f64
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
