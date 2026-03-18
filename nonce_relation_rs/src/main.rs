use anyhow::{Result, Context, anyhow};
use clap::Parser;
use k256::elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar, NonZeroScalar};
use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::{Num, One, Zero};
use ripemd::{Digest as RipemdDigest, Ripemd160};
use serde::Deserialize;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use rayon::prelude::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    sigs: String,

    #[arg(short, long)]
    address: Option<String>,

    #[arg(short, long)]
    pubkey: Option<String>,

    #[arg(short, long, default_value_t = 100)]
    limit: u64,

    #[arg(short, long)]
    verbose: bool,
}

#[derive(Deserialize, Debug)]
struct SigRaw {
    r: serde_json::Value,
    s: serde_json::Value,
    z: serde_json::Value,
    txid: Option<String>,
}

fn value_to_bigint(v: &serde_json::Value) -> BigInt {
    match v {
        serde_json::Value::Number(n) => {
            BigInt::from_str_radix(&n.to_string(), 10).unwrap_or_else(|_| BigInt::zero())
        }
        serde_json::Value::String(s) => {
            BigInt::from_str_radix(s, 10)
                .or_else(|_| BigInt::from_str_radix(s.trim_start_matches("0x"), 16))
                .unwrap_or_else(|_| BigInt::zero())
        }
        _ => BigInt::zero(),
    }
}

struct Sig {
    r: Scalar,
    s: Scalar,
    z: Scalar,
    r_bi: BigInt,
    s_bi: BigInt,
    z_bi: BigInt,
    txid: String,
}

const P_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

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
            if decoded.len() == 25 {
                hashes.push(decoded[1..21].to_vec());
            }
        }
    }
    hashes
}

fn fast_verify(d: &Scalar, target_hashes: &[Vec<u8>], target_pubkey: &Option<ProjectivePoint>) -> bool {
    let sk = k256::ecdsa::SigningKey::from(NonZeroScalar::from_repr(d.to_bytes()).unwrap());
    let vk = sk.verifying_key();
    
    if let Some(target_q) = target_pubkey {
        return ProjectivePoint::from(*vk.as_affine()) == *target_q;
    }

    for compressed in [true, false] {
        let encoded = vk.to_encoded_point(compressed);
        let pubkey_bytes = encoded.as_bytes();
        
        let mut sha256 = Sha256::new();
        sha256.update(pubkey_bytes);
        let sha256_hash = sha256.finalize();
        
        let mut ripemd160 = Ripemd160::new();
        ripemd160.update(sha256_hash);
        let h160 = ripemd160.finalize();
        
        if target_hashes.contains(&h160.to_vec()) {
            return true;
        }
    }
    false
}

fn tonelli_shanks(n: &BigInt, p: &BigInt) -> Option<BigInt> {
    let n = n.mod_floor(p);
    if n.is_zero() { return Some(BigInt::zero()); }
    if n.modpow(&((p - BigInt::one()) / 2u32), p) != BigInt::one() {
        return None;
    }

    let mut s = 0u32;
    let mut q = p - 1u32;
    while q.is_even() {
        q /= 2u32;
        s += 1;
    }

    if s == 1 {
        return Some(n.modpow(&((p + 1u32) / 4u32), p));
    }

    let mut z = BigInt::from(2u32);
    while z.modpow(&((p - BigInt::one()) / 2u32), p) != p - 1u32 {
        z += 1u32;
    }

    let mut c = z.modpow(&q, p);
    let mut r = n.modpow(&((&q + 1u32) / 2u32), p);
    let mut t = n.modpow(&q, p);
    let mut m = s;

    while t != BigInt::one() {
        let mut i = 1u32;
        let mut temp = (&t * &t).mod_floor(p);
        while temp != BigInt::one() && i < m {
            temp = (&temp * &temp).mod_floor(p);
            i += 1;
        }
        if i == m { return None; }
        
        let mut b = c.clone();
        for _ in 0..(m - i - 1) {
            b = (&b * &b).mod_floor(p);
        }
        m = i;
        c = (&b * &b).mod_floor(p);
        t = (&t * &c).mod_floor(p);
        r = (&r * &b).mod_floor(p);
    }
    Some(r)
}

fn solve_quadratic_mod(a: &BigInt, b: &BigInt, c: &BigInt, p: &BigInt) -> Vec<BigInt> {
    if a.is_zero() {
        if b.is_zero() { return vec![]; }
        let b_inv = b.extended_gcd(p).x;
        return vec![( (-c * b_inv).mod_floor(p) + p ) % p];
    }

    let disc = (b * b - BigInt::from(4u32) * a * c).mod_floor(p);
    if let Some(sqrt_d) = tonelli_shanks(&disc, p) {
        let inv_2a = (BigInt::from(2u32) * a).extended_gcd(p).x;
        let x1 = ((-b.clone() + &sqrt_d) * &inv_2a).mod_floor(p);
        let x2 = ((-b.clone() - &sqrt_d) * &inv_2a).mod_floor(p);
        if x1 == x2 { vec![x1] } else { vec![x1, x2] }
    } else {
        vec![]
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let p_bi = BigInt::from_str_radix(P_HEX, 16).unwrap();
    let g = ProjectivePoint::GENERATOR;

    let file = File::open(&args.sigs).context("Failed to open sigs file")?;
    let reader = BufReader::new(file);
    let sigs_raw: Vec<SigRaw> = serde_json::from_reader(reader).context("Failed to parse JSON")?;

    let sigs: Vec<Sig> = sigs_raw.into_iter().enumerate().map(|(i, s)| {
        let r_bi = value_to_bigint(&s.r);
        let s_bi = value_to_bigint(&s.s);
        let z_bi = value_to_bigint(&s.z);
        Sig {
            r: bigint_to_scalar(&r_bi),
            s: bigint_to_scalar(&s_bi),
            z: bigint_to_scalar(&z_bi),
            r_bi, s_bi, z_bi,
            txid: s.txid.unwrap_or_else(|| format!("sig_{}", i)),
        }
    }).collect();

    let target_hashes = args.address.as_ref().map(|a| get_target_hashes(a)).unwrap_or_default();
    let target_pubkey = args.pubkey.as_ref().and_then(|pk| {
        let bytes = hex::decode(pk.trim_start_matches("0x")).ok()?;
        let encoded = k256::EncodedPoint::from_bytes(&bytes).ok()?;
        ProjectivePoint::from_encoded_point(&encoded).into()
    });

    if target_hashes.is_empty() && target_pubkey.is_none() {
        return Err(anyhow!("Must provide either --address or --pubkey"));
    }

    println!("Loaded {} signatures.", sigs.len());

    // 1. Point-based Delta Scan O(N)
    if let Some(q) = target_pubkey {
        println!("Running O(N) Point Delta Scan (k_i = k_j + delta)...");
        let points: Vec<ProjectivePoint> = sigs.par_iter().map(|sig| {
            let s_inv = sig.s.invert().unwrap();
            (g * sig.z + q * sig.r) * s_inv
        }).collect();

        let mut point_map = HashMap::new();
        for (i, p) in points.iter().enumerate() {
            point_map.insert(p.to_encoded_point(true).to_bytes().to_vec(), i);
        }

        for delta in 1..=args.limit {
            let dg = g * Scalar::from(delta);
            for (i, p) in points.iter().enumerate() {
                let target_p = p - &dg;
                if let Some(&j) = point_map.get(&target_p.to_encoded_point(true).to_bytes().to_vec()) {
                    if i != j {
                        let delta_s = Scalar::from(delta);
                        let num = delta_s * sigs[i].s * sigs[j].s + sigs[i].s * sigs[j].z - sigs[j].s * sigs[i].z;
                        let den = sigs[j].s * sigs[i].r - sigs[i].s * sigs[j].r;
                        if den != Scalar::ZERO {
                            let d = num * den.invert().unwrap();
                            if fast_verify(&d, &target_hashes, &target_pubkey) {
                                println!("!!! SUCCESS !!! Relation found: k_{} = k_{} + {}", i, j, delta);
                                println!("Private Key: 0x{}", hex::encode(d.to_bytes()));
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Polynonce Linear O(N)
    println!("Running Polynonce Linear Attack...");
    for i in 0..sigs.len().saturating_sub(3) {
        let subset = &sigs[i..i+4];
        let mut u = Vec::new();
        let mut t = Vec::new();
        for sig in subset {
            let s_inv = sig.s_bi.extended_gcd(&p_bi).x;
            u.push((&s_inv * &sig.z_bi).mod_floor(&p_bi));
            t.push((&s_inv * &sig.r_bi).mod_floor(&p_bi));
        }

        let a1 = (&u[2] - &u[1]).mod_floor(&p_bi);
        let b1 = (&t[2] - &t[1]).mod_floor(&p_bi);
        let c1 = (&u[1] - &u[0]).mod_floor(&p_bi);
        let d1 = (&t[1] - &t[0]).mod_floor(&p_bi);
        
        let a2 = (&u[3] - &u[2]).mod_floor(&p_bi);
        let b2 = (&t[3] - &t[2]).mod_floor(&p_bi);
        
        let coeff_a = (&b1 * &b1 - &b2 * &d1).mod_floor(&p_bi);
        let coeff_b = (&a1 * &b1 + &b1 * &a1 - &a2 * &d1 - &b2 * &c1).mod_floor(&p_bi);
        let coeff_c = (&a1 * &a1 - &a2 * &c1).mod_floor(&p_bi);

        let candidates = solve_quadratic_mod(&coeff_a, &coeff_b, &coeff_c, &p_bi);
        for d_bi in candidates {
            let d = bigint_to_scalar(&d_bi);
            if fast_verify(&d, &target_hashes, &target_pubkey) {
                println!("!!! SUCCESS !!! Polynonce Linear found at index {}", i);
                println!("Private Key: 0x{}", hex::encode(d.to_bytes()));
                return Ok(());
            }
        }
    }

    // 3. Brute Force Point Ratios O(N^2 * Ratios)
    if let Some(q) = target_pubkey {
        println!("Running Optimized O(N*L) Point Ratio Scan (a*k_i = b*k_j)...");
        let points: Vec<ProjectivePoint> = sigs.par_iter().map(|sig| {
            let s_inv = sig.s.invert().unwrap();
            (g * sig.z + q * sig.r) * s_inv
        }).collect();

        let mut lookup = HashMap::new();
        
        // Phase 1: Build lookup table
        for i in 0..points.len() {
            for a in 1..=args.limit {
                let ap = points[i] * Scalar::from(a);
                // Store the first occurrence of this point
                lookup.entry(ap.to_encoded_point(true)).or_insert((i, a));
            }
        }

        // Phase 2: Search for matches
        for j in 0..points.len() {
            for b in 1..=args.limit {
                let bp = points[j] * Scalar::from(b);
                if let Some(&(i, a)) = lookup.get(&bp.to_encoded_point(true)) {
                    if i == j && a == b { continue; } // Skip self-match
                    
                    let s1_inv = sigs[i].s.invert().unwrap();
                    let s2_inv = sigs[j].s.invert().unwrap();
                    let a_s = Scalar::from(a);
                    let b_s = Scalar::from(b);
                    
                    let num = b_s * s2_inv * sigs[j].z - a_s * s1_inv * sigs[i].z;
                    let den = a_s * s1_inv * sigs[i].r - b_s * s2_inv * sigs[j].r;
                    
                    if den != Scalar::ZERO {
                        let d = num * den.invert().unwrap();
                        if fast_verify(&d, &target_hashes, &target_pubkey) {
                            println!("!!! SUCCESS !!! Ratio found: {}*k_{} = {}*k_{}", a, i, b, j);
                            println!("Private Key: 0x{}", hex::encode(d.to_bytes()));
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    println!("No relations found.");
    Ok(())
}
