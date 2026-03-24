//! Generates synthetic ECDSA signatures with known weakness patterns.
//!
//! Each weakness type produces signatures where the nonce k has a specific flaw,
//! allowing us to verify that our attack algorithms can recover the private key,
//! and to learn which feature patterns correspond to which vulnerability.

use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::scalar::FromUintUnchecked;
use k256::{ProjectivePoint, Scalar, U256};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{Num, One, Zero};
use rand::Rng;
use sha2::{Digest, Sha256};

/// secp256k1 order
const N_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

/// A generated wallet with known weakness
#[derive(Debug, Clone)]
pub struct SyntheticWallet {
    pub privkey: BigInt,
    pub privkey_hex: String,
    pub address: String,       // simple identifier, not real Bitcoin address
    pub weakness_type: WeaknessType,
    pub weakness_params: String,
    pub signatures: Vec<SyntheticSig>,
}

/// A signature with known nonce
#[derive(Debug, Clone)]
pub struct SyntheticSig {
    pub r: BigInt,
    pub s: BigInt,
    pub z: BigInt,       // message hash
    pub k: BigInt,       // the actual nonce (ground truth)
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum WeaknessType {
    NonceReuse,          // Same k used for 2+ signatures
    RelatedNonce,        // k_i = k_0 + small_delta * i
    BiasedMSB,           // Top B bits of k are zero
    BiasedLSB,           // Bottom B bits of k are zero
    ShortNonce,          // k < 2^B for small B
    LinearCongruential,  // k_i = (a * k_{i-1} + c) mod n
    PrivkeyLeakNonce,    // k = H(privkey || counter)  (deterministic but weak)
    TruncatedRNG,        // k generated from fewer random bits, padded
    Control,             // Properly random nonces (negative examples)
}

impl std::fmt::Display for WeaknessType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WeaknessType::NonceReuse => write!(f, "NonceReuse"),
            WeaknessType::RelatedNonce => write!(f, "RelatedNonce"),
            WeaknessType::BiasedMSB => write!(f, "BiasedMSB"),
            WeaknessType::BiasedLSB => write!(f, "BiasedLSB"),
            WeaknessType::ShortNonce => write!(f, "ShortNonce"),
            WeaknessType::LinearCongruential => write!(f, "LinearCongruential"),
            WeaknessType::PrivkeyLeakNonce => write!(f, "PrivkeyLeakNonce"),
            WeaknessType::TruncatedRNG => write!(f, "TruncatedRNG"),
            WeaknessType::Control => write!(f, "Control"),
        }
    }
}

fn n_bigint() -> BigInt {
    BigInt::from_str_radix(N_HEX, 16).unwrap()
}

/// Generate a random BigInt in [1, n-1]
fn random_scalar(rng: &mut impl Rng) -> BigInt {
    let n = n_bigint();
    loop {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        let val = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes);
        let val = val.mod_floor(&n);
        if !val.is_zero() {
            return val;
        }
    }
}

/// Convert BigInt to k256 Scalar
fn bigint_to_scalar(bi: &BigInt) -> Scalar {
    let n = n_bigint();
    let reduced = bi.mod_floor(&n);
    let bytes = reduced.to_bytes_be().1;
    let mut padded = [0u8; 32];
    let start = 32 - bytes.len().min(32);
    let b_start = bytes.len().saturating_sub(32);
    padded[start..].copy_from_slice(&bytes[b_start..]);
    let uint = U256::from_be_slice(&padded);
    Scalar::from_uint_unchecked(uint)
}

/// Generate an ECDSA signature with a specified nonce k
fn sign_with_nonce(privkey: &BigInt, k: &BigInt, z: &BigInt) -> Option<SyntheticSig> {
    let n = n_bigint();

    let k_scalar = bigint_to_scalar(k);
    if k_scalar.is_zero().into() {
        return None;
    }

    // R = k * G
    let r_point = ProjectivePoint::GENERATOR * k_scalar;
    let r_affine = r_point.to_affine();

    // r = R.x mod n
    let r_bytes = r_affine.x();
    let r_bi = BigInt::from_bytes_be(num_bigint::Sign::Plus, r_bytes.as_slice());
    let r_mod = r_bi.mod_floor(&n);
    if r_mod.is_zero() {
        return None;
    }

    // s = k^{-1} * (z + r * d) mod n
    let k_inv = k.extended_gcd(&n).x.mod_floor(&n);
    let s_bi = (&k_inv * (z + &r_mod * privkey)).mod_floor(&n);
    if s_bi.is_zero() {
        return None;
    }

    Some(SyntheticSig {
        r: r_mod,
        s: s_bi,
        z: z.clone(),
        k: k.clone(),
    })
}

/// Generate a random message hash
fn random_z(rng: &mut impl Rng) -> BigInt {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes)
}

/// Generate a wallet label from index
fn wallet_label(weakness: WeaknessType, idx: usize) -> String {
    format!("SYN_{}_{}",weakness, idx)
}

// ============ WEAKNESS GENERATORS ============

/// NonceReuse: Same k used for 2+ signatures (trivially exploitable)
pub fn gen_nonce_reuse(rng: &mut impl Rng, idx: usize, num_sigs: usize) -> SyntheticWallet {
    let n = n_bigint();
    let privkey = random_scalar(rng);
    let shared_k = random_scalar(rng);

    let mut sigs = Vec::new();
    for _ in 0..num_sigs {
        let z = random_z(rng);
        if let Some(sig) = sign_with_nonce(&privkey, &shared_k, &z) {
            sigs.push(sig);
        }
    }

    SyntheticWallet {
        privkey_hex: format!("{:064x}", &privkey.mod_floor(&n)),
        address: wallet_label(WeaknessType::NonceReuse, idx),
        weakness_type: WeaknessType::NonceReuse,
        weakness_params: "shared_k=1".to_string(),
        privkey,
        signatures: sigs,
    }
}

/// RelatedNonce: k_i = k_0 + delta * i, where delta is small
pub fn gen_related_nonce(rng: &mut impl Rng, idx: usize, num_sigs: usize, delta: u64) -> SyntheticWallet {
    let n = n_bigint();
    let privkey = random_scalar(rng);
    let k_base = random_scalar(rng);

    let mut sigs = Vec::new();
    for i in 0..num_sigs {
        let k = (&k_base + BigInt::from(delta * i as u64)).mod_floor(&n);
        let z = random_z(rng);
        if let Some(sig) = sign_with_nonce(&privkey, &k, &z) {
            sigs.push(sig);
        }
    }

    SyntheticWallet {
        privkey_hex: format!("{:064x}", &privkey.mod_floor(&n)),
        address: wallet_label(WeaknessType::RelatedNonce, idx),
        weakness_type: WeaknessType::RelatedNonce,
        weakness_params: format!("delta={}", delta),
        privkey,
        signatures: sigs,
    }
}

/// BiasedMSB: Top `bias_bits` bits of k are zero
pub fn gen_biased_msb(rng: &mut impl Rng, idx: usize, num_sigs: usize, bias_bits: usize) -> SyntheticWallet {
    let n = n_bigint();
    let privkey = random_scalar(rng);

    let effective_bits = 256 - bias_bits;
    let mask = (BigInt::one() << effective_bits) - BigInt::one();

    let mut sigs = Vec::new();
    for _ in 0..num_sigs {
        let mut k = random_scalar(rng) & &mask;
        if k.is_zero() { k = BigInt::one(); }
        k = k.mod_floor(&n);
        let z = random_z(rng);
        if let Some(sig) = sign_with_nonce(&privkey, &k, &z) {
            sigs.push(sig);
        }
    }

    SyntheticWallet {
        privkey_hex: format!("{:064x}", &privkey.mod_floor(&n)),
        address: wallet_label(WeaknessType::BiasedMSB, idx),
        weakness_type: WeaknessType::BiasedMSB,
        weakness_params: format!("bias_bits={}", bias_bits),
        privkey,
        signatures: sigs,
    }
}

/// BiasedLSB: Bottom `bias_bits` bits of k are zero
pub fn gen_biased_lsb(rng: &mut impl Rng, idx: usize, num_sigs: usize, bias_bits: usize) -> SyntheticWallet {
    let n = n_bigint();
    let privkey = random_scalar(rng);

    let mut sigs = Vec::new();
    for _ in 0..num_sigs {
        let mut k = random_scalar(rng);
        k = (&k >> bias_bits) << bias_bits; // zero out bottom bits
        if k.is_zero() { k = BigInt::one() << bias_bits; }
        k = k.mod_floor(&n);
        let z = random_z(rng);
        if let Some(sig) = sign_with_nonce(&privkey, &k, &z) {
            sigs.push(sig);
        }
    }

    SyntheticWallet {
        privkey_hex: format!("{:064x}", &privkey.mod_floor(&n)),
        address: wallet_label(WeaknessType::BiasedLSB, idx),
        weakness_type: WeaknessType::BiasedLSB,
        weakness_params: format!("bias_bits={}", bias_bits),
        privkey,
        signatures: sigs,
    }
}

/// ShortNonce: k < 2^short_bits (very small nonce)
pub fn gen_short_nonce(rng: &mut impl Rng, idx: usize, num_sigs: usize, short_bits: usize) -> SyntheticWallet {
    let n = n_bigint();
    let privkey = random_scalar(rng);
    let mask = (BigInt::one() << short_bits) - BigInt::one();

    let mut sigs = Vec::new();
    for _ in 0..num_sigs {
        let mut k = random_scalar(rng) & &mask;
        if k.is_zero() { k = BigInt::one(); }
        k = k.mod_floor(&n);
        let z = random_z(rng);
        if let Some(sig) = sign_with_nonce(&privkey, &k, &z) {
            sigs.push(sig);
        }
    }

    SyntheticWallet {
        privkey_hex: format!("{:064x}", &privkey.mod_floor(&n)),
        address: wallet_label(WeaknessType::ShortNonce, idx),
        weakness_type: WeaknessType::ShortNonce,
        weakness_params: format!("short_bits={}", short_bits),
        privkey,
        signatures: sigs,
    }
}

/// LinearCongruential: k_i = (a * k_{i-1} + c) mod n
pub fn gen_linear_congruential(rng: &mut impl Rng, idx: usize, num_sigs: usize) -> SyntheticWallet {
    let n = n_bigint();
    let privkey = random_scalar(rng);
    let a = random_scalar(rng);
    let c = random_scalar(rng);

    let mut k = random_scalar(rng);
    let mut sigs = Vec::new();
    for _ in 0..num_sigs {
        let z = random_z(rng);
        if let Some(sig) = sign_with_nonce(&privkey, &k, &z) {
            sigs.push(sig);
        }
        k = (&a * &k + &c).mod_floor(&n);
        if k.is_zero() { k = BigInt::one(); }
    }

    SyntheticWallet {
        privkey_hex: format!("{:064x}", &privkey.mod_floor(&n)),
        address: wallet_label(WeaknessType::LinearCongruential, idx),
        weakness_type: WeaknessType::LinearCongruential,
        weakness_params: format!("lcg_a={:064x},lcg_c={:064x}", &a.mod_floor(&n), &c.mod_floor(&n)),
        privkey,
        signatures: sigs,
    }
}

/// PrivkeyLeakNonce: k = SHA256(privkey || counter) — deterministic but key-dependent
pub fn gen_privkey_leak_nonce(rng: &mut impl Rng, idx: usize, num_sigs: usize) -> SyntheticWallet {
    let n = n_bigint();
    let privkey = random_scalar(rng);

    let pk_bytes = {
        let reduced = privkey.mod_floor(&n);
        let b = reduced.to_bytes_be().1;
        let mut padded = vec![0u8; 32 - b.len().min(32)];
        padded.extend_from_slice(&b[b.len().saturating_sub(32)..]);
        padded
    };

    let mut sigs = Vec::new();
    for i in 0..num_sigs {
        let mut hasher = Sha256::new();
        hasher.update(&pk_bytes);
        hasher.update(i.to_le_bytes());
        let k_bytes = hasher.finalize();
        let mut k = BigInt::from_bytes_be(num_bigint::Sign::Plus, &k_bytes);
        k = k.mod_floor(&n);
        if k.is_zero() { continue; }

        let z = random_z(rng);
        if let Some(sig) = sign_with_nonce(&privkey, &k, &z) {
            sigs.push(sig);
        }
    }

    SyntheticWallet {
        privkey_hex: format!("{:064x}", &privkey.mod_floor(&n)),
        address: wallet_label(WeaknessType::PrivkeyLeakNonce, idx),
        weakness_type: WeaknessType::PrivkeyLeakNonce,
        weakness_params: "k=SHA256(privkey||counter)".to_string(),
        privkey,
        signatures: sigs,
    }
}

/// TruncatedRNG: Only `rng_bits` of randomness, rest is zero-padded
pub fn gen_truncated_rng(rng: &mut impl Rng, idx: usize, num_sigs: usize, rng_bits: usize) -> SyntheticWallet {
    let n = n_bigint();
    let privkey = random_scalar(rng);

    let mut sigs = Vec::new();
    for _ in 0..num_sigs {
        // Generate rng_bits of randomness in the lower bits
        let rng_bytes = (rng_bits + 7) / 8;
        let mut k_bytes = vec![0u8; 32];
        for b in k_bytes[32 - rng_bytes..].iter_mut() {
            *b = rng.gen();
        }
        // Mask off excess bits
        if rng_bits % 8 != 0 {
            k_bytes[32 - rng_bytes] &= (1u8 << (rng_bits % 8)) - 1;
        }
        let mut k = BigInt::from_bytes_be(num_bigint::Sign::Plus, &k_bytes);
        k = k.mod_floor(&n);
        if k.is_zero() { continue; }

        let z = random_z(rng);
        if let Some(sig) = sign_with_nonce(&privkey, &k, &z) {
            sigs.push(sig);
        }
    }

    SyntheticWallet {
        privkey_hex: format!("{:064x}", &privkey.mod_floor(&n)),
        address: wallet_label(WeaknessType::TruncatedRNG, idx),
        weakness_type: WeaknessType::TruncatedRNG,
        weakness_params: format!("rng_bits={}", rng_bits),
        privkey,
        signatures: sigs,
    }
}

/// Control: Properly random nonces (should NOT be exploitable)
pub fn gen_control(rng: &mut impl Rng, idx: usize, num_sigs: usize) -> SyntheticWallet {
    let n = n_bigint();
    let privkey = random_scalar(rng);

    let mut sigs = Vec::new();
    for _ in 0..num_sigs {
        let k = random_scalar(rng);
        let z = random_z(rng);
        if let Some(sig) = sign_with_nonce(&privkey, &k, &z) {
            sigs.push(sig);
        }
    }

    SyntheticWallet {
        privkey_hex: format!("{:064x}", &privkey.mod_floor(&n)),
        address: wallet_label(WeaknessType::Control, idx),
        weakness_type: WeaknessType::Control,
        weakness_params: "random".to_string(),
        privkey,
        signatures: sigs,
    }
}

/// Generate a full training dataset with varied difficulty levels
pub fn generate_training_set(rng: &mut impl Rng) -> Vec<SyntheticWallet> {
    let mut wallets = Vec::new();
    let mut idx = 0;

    println!("[Generator] Creating synthetic vulnerable wallets...");

    // NonceReuse: trivial — baseline for the solver
    for _ in 0..20 {
        for num_sigs in [2, 3, 5, 10] {
            wallets.push(gen_nonce_reuse(rng, idx, num_sigs));
            idx += 1;
        }
    }
    println!("  NonceReuse: {} wallets", idx);

    // RelatedNonce: varying delta sizes
    let base = idx;
    for delta in [1u64, 2, 5, 10, 100, 1000, 10000] {
        for num_sigs in [2, 5, 10, 20] {
            for _ in 0..5 {
                wallets.push(gen_related_nonce(rng, idx, num_sigs, delta));
                idx += 1;
            }
        }
    }
    println!("  RelatedNonce: {} wallets", idx - base);

    // BiasedMSB: varying bias (8, 16, 32, 64, 128 bits zeroed)
    let base = idx;
    for bias_bits in [8, 16, 32, 48, 64, 96, 128] {
        for num_sigs in [5, 10, 20, 40] {
            for _ in 0..5 {
                wallets.push(gen_biased_msb(rng, idx, num_sigs, bias_bits));
                idx += 1;
            }
        }
    }
    println!("  BiasedMSB: {} wallets", idx - base);

    // BiasedLSB: varying bias
    let base = idx;
    for bias_bits in [8, 16, 32, 64, 128] {
        for num_sigs in [5, 10, 20, 40] {
            for _ in 0..5 {
                wallets.push(gen_biased_lsb(rng, idx, num_sigs, bias_bits));
                idx += 1;
            }
        }
    }
    println!("  BiasedLSB: {} wallets", idx - base);

    // ShortNonce: nonce < 2^B
    let base = idx;
    for short_bits in [32, 64, 96, 128, 160] {
        for num_sigs in [2, 5, 10] {
            for _ in 0..5 {
                wallets.push(gen_short_nonce(rng, idx, num_sigs, short_bits));
                idx += 1;
            }
        }
    }
    println!("  ShortNonce: {} wallets", idx - base);

    // LinearCongruential
    let base = idx;
    for num_sigs in [5, 10, 20, 50] {
        for _ in 0..10 {
            wallets.push(gen_linear_congruential(rng, idx, num_sigs));
            idx += 1;
        }
    }
    println!("  LinearCongruential: {} wallets", idx - base);

    // PrivkeyLeakNonce
    let base = idx;
    for num_sigs in [5, 10, 20] {
        for _ in 0..10 {
            wallets.push(gen_privkey_leak_nonce(rng, idx, num_sigs));
            idx += 1;
        }
    }
    println!("  PrivkeyLeakNonce: {} wallets", idx - base);

    // TruncatedRNG: varying entropy
    let base = idx;
    for rng_bits in [64, 96, 128, 160, 192, 224] {
        for num_sigs in [5, 10, 20, 40] {
            for _ in 0..5 {
                wallets.push(gen_truncated_rng(rng, idx, num_sigs, rng_bits));
                idx += 1;
            }
        }
    }
    println!("  TruncatedRNG: {} wallets", idx - base);

    // Control: properly random (negative examples)
    let base = idx;
    for num_sigs in [5, 10, 20, 40] {
        for _ in 0..25 {
            wallets.push(gen_control(rng, idx, num_sigs));
            idx += 1;
        }
    }
    println!("  Control: {} wallets", idx - base);

    println!("[Generator] Total: {} wallets, {} signatures",
        wallets.len(),
        wallets.iter().map(|w| w.signatures.len()).sum::<usize>()
    );

    wallets
}
