use anyhow::{anyhow, Result};
use k256::{ProjectivePoint, Scalar};
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::PrimeField;
use num_bigint::{BigInt, Sign};
use num_traits::Num;
use rayon::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const P_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

struct Kangaroo {
    pubkey: ProjectivePoint,
    lower: BigInt,
    upper: BigInt,
    num_tame: usize,
    num_wild: usize,
}

impl Kangaroo {
    fn new(pubkey_hex: &str, lower: BigInt, upper: BigInt) -> Result<Self> {
        let pubkey_bytes = hex::decode(pubkey_hex)?;
        let pubkey_opt = ProjectivePoint::from_bytes(pubkey_bytes.as_slice().try_into()?);
        
        if pubkey_opt.is_none().into() {
            return Err(anyhow!("Invalid pubkey"));
        }
        
        Ok(Self {
            pubkey: pubkey_opt.unwrap(),
            lower,
            upper,
            num_tame: 1024,
            num_wild: 1024,
        })
    }

    fn jump_size(point_bytes: &[u8]) -> usize {
        let s = point_bytes[point_bytes.len()-1] as usize % 32;
        1 << s
    }

    fn is_distinguished(point_bytes: &[u8]) -> bool {
        point_bytes[0] == 0 && point_bytes[1] < 4 
    }

    pub fn solve(&self) -> Result<BigInt> {
        let n_bi = BigInt::from_str_radix(P_HEX, 16).unwrap();
        let range = &self.upper - &self.lower;
        
        println!("[*] Range: {} to {}", self.lower, self.upper);
        println!("[*] Range size: {}", range);

        let traps = Arc::new(Mutex::new(HashMap::new()));
        let solution = Arc::new(Mutex::new(None));

        let g = ProjectivePoint::GENERATOR;

        // Tame Kangaroos
        println!("[*] Releasing {} tame kangaroos...", self.num_tame);
        (0..self.num_tame).into_par_iter().for_each(|i| {
            let mut pos = BigInt::from(i) * (&range / self.num_tame);
            let mut current_point = g * bigint_to_scalar(&pos);

            for _ in 0..1000000 {
                if solution.lock().unwrap().is_some() { return; }
                let bytes = current_point.to_bytes().to_vec();
                if Self::is_distinguished(&bytes) {
                    traps.lock().unwrap().insert(bytes.clone(), pos.clone());
                }
                let jump = Self::jump_size(&bytes);
                pos += jump;
                current_point += g * bigint_to_scalar(&BigInt::from(jump));
            }
        });

        // Wild Kangaroos
        println!("[*] Releasing {} wild kangaroos...", self.num_wild);
        (0..self.num_wild).into_par_iter().for_each(|_i| {
            let mut dist = BigInt::from(0);
            let mut current_point = self.pubkey - (g * bigint_to_scalar(&self.lower));
            
            for _ in 0..2000000 {
                if solution.lock().unwrap().is_some() { return; }
                let bytes = current_point.to_bytes().to_vec();
                if Self::is_distinguished(&bytes) {
                    if let Some(tame_pos) = traps.lock().unwrap().get(&bytes) {
                        let target_priv = (tame_pos + &self.lower - &dist).mod_floor(&n_bi);
                        *solution.lock().unwrap() = Some(target_priv);
                        return;
                    }
                }
                let jump = Self::jump_size(&bytes);
                dist += jump;
                current_point -= g * bigint_to_scalar(&BigInt::from(jump));
            }
        });

        let res = solution.lock().unwrap().clone();
        res.ok_or_else(|| anyhow!("Kangaroo failed to find key in range"))
    }
}

fn bigint_to_scalar(bi: &BigInt) -> Scalar {
    let n_bi = BigInt::from_str_radix(P_HEX, 16).unwrap();
    let reduced = bi.mod_floor(&n_bi);
    let bytes = reduced.to_bytes_be().1;
    let mut padded = [0u8; 32];
    let start = 32 - bytes.len().min(32);
    let b_start = bytes.len().saturating_sub(32);
    padded[start..].copy_from_slice(&bytes[b_start..]);
    Scalar::from_repr(padded.into()).unwrap()
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        println!("Usage: kangaroo_rs <pubkey_hex> <lower_hex> <upper_hex>");
        return Ok(());
    }

    let pubkey = &args[1];
    let lower = BigInt::from_str_radix(args[2].trim_start_matches("0x"), 16)?;
    let upper = BigInt::from_str_radix(args[3].trim_start_matches("0x"), 16)?;

    let scouter = Kangaroo::new(pubkey, lower, upper)?;
    match scouter.solve() {
        Ok(privkey) => println!("!!! SUCCESS !!! Private Key: 0x{:x}", privkey),
        Err(e) => println!("Failed: {}", e),
    }

    Ok(())
}

trait BigIntExt {
    fn mod_floor(&self, n: &BigInt) -> BigInt;
}

impl BigIntExt for BigInt {
    fn mod_floor(&self, n: &BigInt) -> BigInt {
        let res = self % n;
        if res.sign() == Sign::Minus { res + n } else { res }
    }
}
