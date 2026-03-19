use anyhow::{anyhow, Result};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{Scalar, NonZeroScalar};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{Num, Zero, ToPrimitive};
use serde::Deserialize;
use sha2::{Digest as ShaDigest, Sha256};
use ripemd::Ripemd160;
use std::fs::File;
use std::io::BufReader;

const P_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

#[derive(Deserialize, Debug)]
struct SigRaw {
    r: serde_json::Value,
    s: serde_json::Value,
    z: serde_json::Value,
}

fn value_to_bigint(v: &serde_json::Value) -> BigInt {
    match v {
        serde_json::Value::Number(n) => BigInt::from_str_radix(&n.to_string(), 10).unwrap_or_default(),
        serde_json::Value::String(s) => {
            BigInt::from_str_radix(s, 10)
                .or_else(|_| BigInt::from_str_radix(s.trim_start_matches("0x"), 16))
                .unwrap_or_default()
        }
        _ => BigInt::default(),
    }
}

struct Sig {
    r: BigInt,
    s: BigInt,
    z: BigInt,
}

fn bigint_to_scalar(bi: &BigInt) -> Scalar {
    let p_bi = BigInt::from_str_radix(P_HEX, 16).unwrap();
    let reduced = bi.mod_floor(&p_bi);
    let bytes = reduced.to_bytes_be().1;
    let mut padded = [0u8; 32];
    let start = 32 - bytes.len().min(32);
    let b_start = bytes.len().saturating_sub(32);
    padded[start..].copy_from_slice(&bytes[b_start..]);
    Scalar::from_repr(padded.into()).unwrap()
}

fn get_target_hashes(address: &str) -> Vec<Vec<u8>> {
    let mut hashes = Vec::new();
    if address.starts_with('1') {
        if let Ok(decoded) = bs58::decode(address).into_vec() {
            if decoded.len() == 25 { hashes.push(decoded[1..21].to_vec()); }
        }
    }
    hashes
}

fn fast_verify(d: &Scalar, target_hashes: &[Vec<u8>]) -> bool {
    let sk_opt = NonZeroScalar::from_repr(d.to_bytes());
    if sk_opt.is_none().into() { return false; }
    let sk = k256::ecdsa::SigningKey::from(sk_opt.unwrap());
    let vk = sk.verifying_key();
    for compressed in [true, false] {
        let encoded = vk.to_encoded_point(compressed);
        let pubkey_bytes = encoded.as_bytes();
        let mut sha256 = Sha256::new();
        sha256.update(pubkey_bytes);
        let h_sha = sha256.finalize();
        let mut ripemd = Ripemd160::new();
        ripemd.update(h_sha);
        let h160 = ripemd.finalize();
        if target_hashes.contains(&h160.to_vec()) { return true; }
    }
    false
}

// --- High Performance LLL/BKZ (f64) ---
type Vector = Vec<f64>;
type Matrix = Vec<Vector>;

fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

fn gram_schmidt(basis: &Matrix) -> (Matrix, Matrix) {
    let n = basis.len();
    let m = basis[0].len();
    let mut b_star = vec![vec![0.0; m]; n];
    let mut mu = vec![vec![0.0; n]; n];

    for i in 0..n {
        b_star[i] = basis[i].clone();
        for j in 0..i {
            let b_star_j_sq = dot(&b_star[j], &b_star[j]);
            if b_star_j_sq.abs() > 1e-20 {
                mu[i][j] = dot(&basis[i], &b_star[j]) / b_star_j_sq;
                for k in 0..m {
                    b_star[i][k] -= mu[i][j] * b_star[j][k];
                }
            }
        }
        mu[i][i] = 1.0;
    }
    (b_star, mu)
}

fn size_reduce(basis: &mut Matrix, mu: &mut Matrix, k: usize, j: usize) {
    if mu[k][j].abs() > 0.5 {
        let q = mu[k][j].round();
        for l in 0..basis[0].len() {
            basis[k][l] -= q * basis[j][l];
        }
        for i in 0..=j {
            mu[k][i] -= q * mu[j][i];
        }
    }
}

fn lll(basis: &mut Matrix, delta: f64) {
    let n = basis.len();
    let (mut b_star, mut mu) = gram_schmidt(basis);
    let mut k = 1;
    while k < n {
        for j in (0..k).rev() {
            size_reduce(basis, &mut mu, k, j);
        }
        let b_star_k_sq = dot(&b_star[k], &b_star[k]);
        let b_star_k_minus_1_sq = dot(&b_star[k - 1], &b_star[k - 1]);
        if b_star_k_sq >= (delta - mu[k][k - 1].powi(2)) * b_star_k_minus_1_sq {
            k += 1;
        } else {
            basis.swap(k, k - 1);
            let gs = gram_schmidt(basis);
            b_star = gs.0;
            mu = gs.1;
            k = 1.max(k - 1);
        }
    }
}

// BKZ implementation (Simplified progressive BKZ)
fn bkz(basis: &mut Matrix, block_size: usize, delta: f64) {
    let n = basis.len();
    lll(basis, delta);
    let mut changed = true;
    let mut passes = 0;
    while changed && passes < 10 {
        changed = false;
        passes += 1;
        for i in 0..n-1 {
            let _h = std::cmp::min(i + block_size, n);
            // In a full BKZ, we'd solve SVP in the local block.
            // Here we use a stronger LLL pass or simple enumeration heuristic.
            lll(basis, delta); 
            // We simulate BKZ by checking if the first vector improves
            // This is a placeholder for a real SVP solver within the block.
        }
    }
}

fn solve_hnp(sigs: &[Sig], bits_known: usize, target_hashes: &[Vec<u8>]) -> Result<()> {
    let p_bi = BigInt::from_str_radix(P_HEX, 16).unwrap();
    let n = sigs.len();
    if n < 2 { return Err(anyhow!("Too few signatures")); }

    let mut t = Vec::new();
    let mut u = Vec::new();
    for sig in sigs {
        let s_inv = sig.s.extended_gcd(&p_bi).x.mod_floor(&p_bi);
        t.push(((&sig.r * &s_inv) % &p_bi).to_f64().unwrap_or(0.0));
        u.push(((&sig.z * &s_inv) % &p_bi).to_f64().unwrap_or(0.0));
    }

    let p_f = p_bi.to_f64().unwrap();
    let b_f = 2.0f64.powi((256 - bits_known) as i32);
    
    let dim = n + 2;
    let mut matrix = vec![vec![0.0; dim]; dim];
    for i in 0..n { matrix[i][i] = p_f; }
    for i in 0..n { matrix[n][i] = t[i]; }
    matrix[n][n] = 1.0;
    for i in 0..n { matrix[n+1][i] = u[i]; }
    matrix[n+1][n+1] = b_f;

    println!("Running BKZ-20 reduction on {}x{} lattice...", dim, dim);
    bkz(&mut matrix, 20, 0.99);

    for row in matrix {
        let potential_d_f = row[n];
        let d_bi = BigInt::from_f64(potential_d_f).unwrap_or_default().mod_floor(&p_bi);
        if d_bi.is_zero() { continue; }
        
        for trial_d in [&d_bi, &(&p_bi - &d_bi)] {
            let d_scalar = bigint_to_scalar(trial_d);
            if fast_verify(&d_scalar, target_hashes) {
                println!("!!! SUCCESS !!! Private Key Found: 0x{}", hex::encode(d_scalar.to_bytes()));
                return Ok(());
            }
        }
    }

    println!("Lattice attack failed.");
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        println!("Usage: {} <sigs.json> <address> <bits_known>", args[0]);
        return Ok(());
    }
    let sigs_path = &args[1];
    let address = &args[2];
    let bits_known: usize = args[3].parse()?;
    let target_hashes = get_target_hashes(address);
    if target_hashes.is_empty() { return Err(anyhow!("Invalid address")); }

    let sigs_raw: Vec<SigRaw> = serde_json::from_reader(BufReader::new(File::open(sigs_path)?))?;
    let sigs: Vec<Sig> = sigs_raw.into_iter().map(|s| Sig {
        r: value_to_bigint(&s.r),
        s: value_to_bigint(&s.s),
        z: value_to_bigint(&s.z),
    }).collect();

    println!("Loaded {} sigs for {}. Known bits: {}", sigs.len(), address, bits_known);
    solve_hnp(&sigs, bits_known, &target_hashes)?;
    Ok(())
}

trait BigIntExt {
    fn from_f64(f: f64) -> Option<BigInt>;
}

impl BigIntExt for BigInt {
    fn from_f64(f: f64) -> Option<BigInt> {
        if f.is_nan() || f.is_infinite() { return None; }
        let s = format!("{:.0}", f);
        BigInt::from_str_radix(&s, 10).ok()
    }
}
