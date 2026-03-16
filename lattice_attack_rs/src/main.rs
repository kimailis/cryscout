use anyhow::{anyhow, Result};
use k256::elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{Scalar, NonZeroScalar};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{Num, ToPrimitive};
use rusqlite::Connection;
use serde::Deserialize;
use sha2::{Digest as ShaDigest, Sha256};
use ripemd::Ripemd160;
use std::fs::File;
use std::io::BufReader;

const P_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

#[derive(Deserialize, Debug)]
struct SigRaw {
    r: String,
    s: String,
    z: String,
    address: Option<String>,
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
            if decoded.len() == 25 {
                hashes.push(decoded[1..21].to_vec());
            }
        }
    }
    hashes
}

fn fast_verify(d: &Scalar, target_hashes: &[Vec<u8>]) -> bool {
    let sk = k256::ecdsa::SigningKey::from(NonZeroScalar::from_repr(d.to_bytes()).unwrap());
    let vk = sk.verifying_key();
    
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

// --- LLL Implementation (L3) ---
fn gram_schmidt(basis: &Vec<Vec<f64>>, n: usize, m: usize) -> (Vec<Vec<f64>>, Vec<Vec<f64>>) {
    let mut b_star = vec![vec![0.0; m]; n];
    let mut mu = vec![vec![0.0; n]; n];

    for i in 0..n {
        b_star[i] = basis[i].clone();
        for j in 0..i {
            mu[i][j] = dot_product(&basis[i], &b_star[j]) / dot_product(&b_star[j], &b_star[j]);
            for k in 0..m {
                b_star[i][k] -= mu[i][j] * b_star[j][k];
            }
        }
        mu[i][i] = 1.0;
    }
    (b_star, mu)
}

fn dot_product(a: &Vec<f64>, b: &Vec<f64>) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

fn lll_reduction(basis: &mut Vec<Vec<f64>>, delta: f64) {
    let n = basis.len();
    let m = basis[0].len();
    let (mut b_star, mut mu) = gram_schmidt(basis, n, m);

    let mut k = 1;
    while k < n {
        for j in (0..k).rev() {
            if mu[k][j].abs() > 0.5 {
                let q = mu[k][j].round();
                for l in 0..m {
                    basis[k][l] -= q * basis[j][l];
                }
                // Update GS
                (b_star, mu) = gram_schmidt(basis, n, m);
            }
        }

        let lhs = dot_product(&b_star[k], &b_star[k]);
        let rhs = (delta - mu[k][k - 1].powi(2)) * dot_product(&b_star[k - 1], &b_star[k - 1]);

        if lhs >= rhs {
            k += 1;
        } else {
            basis.swap(k, k - 1);
            (b_star, mu) = gram_schmidt(basis, n, m);
            k = 1.max(k - 1);
        }
    }
}

// --- HNP Solver ---
fn solve_hnp(sigs: &[Sig], bits_known: usize, target_hashes: &[Vec<u8>]) -> Result<()> {
    let p_bi = BigInt::from_str_radix(P_HEX, 16).unwrap();
    let n = sigs.len();
    if n < 5 { return Err(anyhow!("Too few signatures")); }

    println!("Constructing lattice for {} signatures ({} bits known)...", n, bits_known);

    let mut t = Vec::new();
    let mut u = Vec::new();
    for sig in sigs {
        let s_inv = sig.s.extended_gcd(&p_bi).x;
        t.push((&sig.r * &s_inv).mod_floor(&p_bi));
        u.push((&sig.z * &s_inv).mod_floor(&p_bi));
    }

    let b_val = BigInt::from(2u32).pow((256 - bits_known) as u32);
    let mut matrix = vec![vec![0.0; n + 2]; n + 2];

    for i in 0..n {
        matrix[i][i] = p_bi.to_f64().unwrap();
    }
    for i in 0..n {
        matrix[n][i] = t[i].to_f64().unwrap();
    }
    matrix[n][n] = 1.0;
    for i in 0..n {
        matrix[n + 1][i] = u[i].to_f64().unwrap();
    }
    matrix[n + 1][n + 1] = b_val.to_f64().unwrap();

    println!("Running LLL reduction...");
    lll_reduction(&mut matrix, 0.75);

    println!("Scanning reduced basis for private key...");
    for row in matrix {
        let potential_d = row[n].abs().round() as i128;
        if potential_d == 0 { continue; }
        
        // Try positive and negative
        let d_bi = BigInt::from(potential_d).mod_floor(&p_bi);
        let d_scalar = bigint_to_scalar(&d_bi);
        if fast_verify(&d_scalar, target_hashes) {
            println!("!!! SUCCESS !!! Private Key Found: 0x{}", hex::encode(d_scalar.to_bytes()));
            return Ok(());
        }

        let d_neg_bi = (-BigInt::from(potential_d)).mod_floor(&p_bi);
        let d_neg_scalar = bigint_to_scalar(&d_neg_bi);
        if fast_verify(&d_neg_scalar, target_hashes) {
            println!("!!! SUCCESS !!! Private Key Found (neg): 0x{}", hex::encode(d_neg_scalar.to_bytes()));
            return Ok(());
        }
    }

    println!("Lattice attack failed to find key.");
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
    if target_hashes.is_empty() {
        return Err(anyhow!("Invalid address"));
    }

    let file = File::open(sigs_path)?;
    let reader = BufReader::new(file);
    let sigs_raw: Vec<SigRaw> = serde_json::from_reader(reader)?;

    let sigs: Vec<Sig> = sigs_raw.into_iter().map(|s| {
        Sig {
            r: BigInt::from_str_radix(&s.r, 10).or_else(|_| BigInt::from_str_radix(s.r.trim_start_matches("0x"), 16)).unwrap_or_default(),
            s: BigInt::from_str_radix(&s.s, 10).or_else(|_| BigInt::from_str_radix(s.s.trim_start_matches("0x"), 16)).unwrap_or_default(),
            z: BigInt::from_str_radix(&s.z, 10).or_else(|_| BigInt::from_str_radix(s.z.trim_start_matches("0x"), 16)).unwrap_or_default(),
        }
    }).collect();

    println!("Loaded {} signatures for address {}", sigs.len(), address);
    solve_hnp(&sigs, bits_known, &target_hashes)?;

    Ok(())
}
