use anyhow::{anyhow, Result};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{Scalar, NonZeroScalar};
use num_bigint::BigInt;
use num_integer::Integer;
use num_rational::BigRational;
use num_traits::{Num, Zero, One, Signed};
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

// --- Arbitrary-Precision LLL using BigRational ---

type BRVec = Vec<BigRational>;
type BRMatrix = Vec<BRVec>;

fn br(n: &BigInt) -> BigRational {
    BigRational::from_integer(n.clone())
}

fn dot_br(a: &[BigRational], b: &[BigRational]) -> BigRational {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

fn gram_schmidt_br(basis: &BRMatrix) -> (BRMatrix, BRMatrix) {
    let n = basis.len();
    let m = basis[0].len();
    let zero = BigRational::zero();
    let mut b_star: BRMatrix = vec![vec![zero.clone(); m]; n];
    let mut mu: BRMatrix = vec![vec![zero.clone(); n]; n];

    for i in 0..n {
        b_star[i] = basis[i].clone();
        for j in 0..i {
            let b_star_j_sq = dot_br(&b_star[j], &b_star[j]);
            if !b_star_j_sq.is_zero() {
                mu[i][j] = dot_br(&basis[i], &b_star[j]) / &b_star_j_sq;
                let mu_ij = mu[i][j].clone();
                for k in 0..m {
                    let sub = &mu_ij * &b_star[j][k];
                    b_star[i][k] = &b_star[i][k] - sub;
                }
            }
        }
        mu[i][i] = BigRational::one();
    }
    (b_star, mu)
}

fn size_reduce_br(basis: &mut BRMatrix, mu: &mut BRMatrix, k: usize, j: usize) {
    let half = BigRational::new(BigInt::from(1), BigInt::from(2));
    if mu[k][j].abs() > half {
        let q = mu[k][j].round();
        let m = basis[0].len();
        for l in 0..m {
            let sub = &q * &basis[j][l];
            basis[k][l] = &basis[k][l] - sub;
        }
        for i in 0..=j {
            let sub = &q * &mu[j][i];
            mu[k][i] = &mu[k][i] - sub;
        }
    }
}

/// Incrementally update Gram-Schmidt after swapping rows k-1 and k.
/// Only rows k-1..n need recomputation (rows 0..k-2 are unchanged).
fn update_gs_after_swap(basis: &BRMatrix, b_star: &mut BRMatrix, mu: &mut BRMatrix, k: usize) {
    let n = basis.len();
    let m = basis[0].len();
    let zero = BigRational::zero();

    // Recompute from row k-1 onward
    for i in (k - 1)..n {
        b_star[i] = basis[i].clone();
        for j in 0..i {
            let b_star_j_sq = dot_br(&b_star[j], &b_star[j]);
            if !b_star_j_sq.is_zero() {
                mu[i][j] = dot_br(&basis[i], &b_star[j]) / &b_star_j_sq;
                let mu_ij = mu[i][j].clone();
                for l in 0..m {
                    let sub = &mu_ij * &b_star[j][l];
                    b_star[i][l] = &b_star[i][l] - sub;
                }
            } else {
                mu[i][j] = zero.clone();
            }
        }
        mu[i][i] = BigRational::one();
        // Clear mu entries beyond i
        for j in (i + 1)..n {
            mu[i][j] = zero.clone();
        }
    }
}

fn lll_br(basis: &mut BRMatrix, delta: &BigRational) {
    let n = basis.len();
    let (mut b_star, mut mu) = gram_schmidt_br(basis);
    let mut k = 1usize;
    while k < n {
        for j in (0..k).rev() {
            size_reduce_br(basis, &mut mu, k, j);
        }
        let b_star_k_sq = dot_br(&b_star[k], &b_star[k]);
        let b_star_km1_sq = dot_br(&b_star[k - 1], &b_star[k - 1]);
        let mu_sq = &mu[k][k - 1] * &mu[k][k - 1];
        let lovasz_rhs = (delta - &mu_sq) * &b_star_km1_sq;
        if b_star_k_sq >= lovasz_rhs {
            k += 1;
        } else {
            basis.swap(k, k - 1);
            update_gs_after_swap(basis, &mut b_star, &mut mu, k);
            k = if k > 1 { k - 1 } else { 1 };
        }
    }
}

/// Select the most biased signatures for the lattice — those with the shortest
/// R-values (most MSB bits zero), which give the lattice the best chance.
fn select_best_sigs(sigs: &[Sig], max_count: usize) -> Vec<&Sig> {
    let mut indexed: Vec<(usize, u64)> = sigs.iter().enumerate()
        .map(|(i, s)| (i, s.r.bits()))
        .collect();
    indexed.sort_by_key(|&(_, bits)| bits);
    indexed.into_iter()
        .take(max_count)
        .map(|(i, _)| &sigs[i])
        .collect()
}

fn try_lattice(sigs_subset: &[&Sig], bits_known: usize, target_hashes: &[Vec<u8>], p_bi: &BigInt) -> Result<Option<String>> {
    let n = sigs_subset.len();
    if n < 2 { return Err(anyhow!("Too few signatures")); }

    let zero = BigRational::zero();

    // Compute t_i = r_i * s_i^{-1} mod p and u_i = z_i * s_i^{-1} mod p
    let mut t: Vec<BigInt> = Vec::new();
    let mut u: Vec<BigInt> = Vec::new();
    for sig in sigs_subset {
        let s_inv = sig.s.extended_gcd(p_bi).x.mod_floor(p_bi);
        t.push((&sig.r * &s_inv).mod_floor(p_bi));
        u.push((&sig.z * &s_inv).mod_floor(p_bi));
    }

    // B = 2^(256 - bits_known)
    let b_bi = BigInt::from(1) << (256 - bits_known);

    // Build the lattice matrix (dim = n+2)
    let dim = n + 2;
    let mut matrix: BRMatrix = vec![vec![zero.clone(); dim]; dim];

    // First n rows: p on diagonal
    for i in 0..n {
        matrix[i][i] = br(p_bi);
    }
    // Row n: t values, then 1
    for i in 0..n {
        matrix[n][i] = br(&t[i]);
    }
    matrix[n][n] = BigRational::one();
    // Row n+1: u values, then 0, then B
    for i in 0..n {
        matrix[n + 1][i] = br(&u[i]);
    }
    matrix[n + 1][n + 1] = br(&b_bi);

    println!("  Running LLL on {}x{} lattice (bits_known={})...", dim, dim, bits_known);
    let delta = BigRational::new(BigInt::from(99), BigInt::from(100));
    lll_br(&mut matrix, &delta);
    println!("  LLL complete, checking candidate keys...");

    let one = BigInt::from(1);

    // Extract candidate private key from reduced basis
    for (row_idx, row) in matrix.iter().enumerate() {
        // The private key candidate is in column n
        let d_numer = row[n].numer();
        let d_denom = row[n].denom();
        // Should be an integer (denom = ±1)
        if d_denom != &one && d_denom != &(-&one) {
            continue;
        }
        let d_bi = if d_denom == &one {
            d_numer.mod_floor(p_bi)
        } else {
            (-d_numer).mod_floor(p_bi)
        };
        if d_bi.is_zero() { continue; }

        for trial_d in [&d_bi, &(p_bi - &d_bi)] {
            let d_scalar = bigint_to_scalar(trial_d);
            if fast_verify(&d_scalar, target_hashes) {
                let key_hex = hex::encode(d_scalar.to_bytes());
                println!("!!! SUCCESS !!! Private Key Found: 0x{} (row {})", key_hex, row_idx);
                return Ok(Some(key_hex));
            }
        }
    }

    Ok(None)
}

fn solve_hnp(sigs: &[Sig], bits_known: usize, target_hashes: &[Vec<u8>]) -> Result<()> {
    let p_bi = BigInt::from_str_radix(P_HEX, 16).unwrap();
    let n = sigs.len();
    if n < 2 { return Err(anyhow!("Too few signatures")); }

    // BigRational LLL is O(n^3) per iteration with large coefficients.
    // Cap at 6 sigs (dim 8) to stay within 180s timeout.
    // Fewer sigs with stronger bias > more sigs with weaker bias.
    let max_sigs = 6;
    let subset_sizes: Vec<usize> = if n <= max_sigs {
        vec![n]
    } else {
        // Try best 4, then best 6
        vec![4, max_sigs]
    };

    for &subset_size in &subset_sizes {
        let best_sigs = select_best_sigs(sigs, subset_size);
        let shortest_bits = best_sigs.iter().map(|s| s.r.bits()).min().unwrap_or(256);
        println!("Trial: {} sigs (shortest R: {} bits), bits_known={}", best_sigs.len(), shortest_bits, bits_known);

        match try_lattice(&best_sigs, bits_known, target_hashes, &p_bi)? {
            Some(_) => return Ok(()),
            None => println!("  No key found with {} sigs, trying larger subset...", subset_size),
        }
    }

    println!("Lattice attack completed — no key recovered.");
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
