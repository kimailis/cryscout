use anyhow::{anyhow, Result};
use num_bigint::{BigInt, Sign};
use num_complex::Complex;
use num_integer::Integer;
use num_traits::{Num, Zero};
use rusqlite::{params, Connection};
use rustfft::{FftPlanner, num_complex::Complex as FftComplex};
use serde::Deserialize;
use std::collections::HashMap;

const P_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const DB_FILE: &str = "cryscout.db";

#[derive(Deserialize, Debug)]
struct SigDb {
    r_hex: String,
    s_hex: String,
    z_hex: String,
}

struct SigHnp {
    t: BigInt,
    u: BigInt,
}

fn solve_hnp_bias(sigs: &[SigHnp], fft_size: usize, min_peak_factor: f64) -> Result<()> {
    if sigs.is_empty() {
        return Err(anyhow!("No signatures to analyze."));
    }

    println!("[*] Preparing FFT of size {} for {} signatures...", fft_size, sigs.len());

    let mut samples: Vec<FftComplex<f64>> = vec![FftComplex::zero(); fft_size];

    let p_bi = BigInt::from_str_radix(P_HEX, 16).unwrap();
    let p_f64 = p_bi.to_string().parse::<f64>().unwrap(); // Approximate

    for sig in sigs {
        // We're looking for a bias in `d` in the equation `k = t*d + u`
        // We can't directly FFT `k`, so we FFT on the `t` term.
        // Simplified approach: bin the `t` values.
        let t_val = sig.t.clone();

        // Convert BigInt `t` to a value between 0 and fft_size
        // This is a simplification; a direct mod is not spectrally correct
        // but can still reveal strong biases.
        let t_f64 = t_val.to_string().parse::<f64>().unwrap_or(0.0);
        let index = ((t_f64 / p_f64) * fft_size as f64) as usize % fft_size;
        
        samples[index].re += 1.0;
    }

    let mut planner = FftPlanner::new();
    let fft = planner.plan_fft_forward(fft_size);

    fft.process(&mut samples);

    println!("[*] Searching for significant peaks in FFT output...");

    let mut magnitudes: Vec<(usize, f64)> = samples.iter()
        .take(fft_size / 2) // We only need the first half (Nyquist limit)
        .enumerate()
        .map(|(i, c)| (i, c.norm()))
        .collect();
    
    // Sort by magnitude to find the largest peaks
    magnitudes.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

    // Calculate average magnitude, excluding DC component (index 0)
    let avg_magnitude: f64 = magnitudes.iter().skip(1).map(|&(_, m)| m).sum::<f64>() / (magnitudes.len() - 1) as f64;

    println!("[*] Average FFT magnitude (noise floor): {:.2}", avg_magnitude);

    let mut found_peaks = false;
    for (freq, mag) in magnitudes.iter().take(10) { // Top 10 peaks
        if *freq == 0 { continue; } // Skip DC
        
        let peak_factor = mag / avg_magnitude;
        if peak_factor > min_peak_factor {
            println!(
                "  [!!!] Potential Bias Found: Frequency bin {} has magnitude {:.2} ({:.1}x avg)",
                freq, mag, peak_factor
            );
            found_peaks = true;
        }
    }
    
    if !found_peaks {
        println!("[*] No significant spectral peaks found above the threshold.");
    }
    
    Ok(())
}


fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <address> [fft_size]", args[0]);
        return Ok(());
    }

    let address = &args[1];
    let fft_size: usize = if args.len() > 2 { args[2].parse()? } else { 1024 * 16 };
    
    let conn = Connection::open(DB_FILE)?;
    let p_bi = BigInt::from_str_radix(P_HEX, 16).unwrap();
    
    println!("[*] Loading signatures for address: {}", address);
    let mut stmt = conn.prepare(
        "SELECT r_hex, s_hex, z_hex FROM signatures WHERE address = ?1",
    )?;
    
    let sig_iter = stmt.query_map(params![address], |row| {
        Ok(SigDb {
            r_hex: row.get(0)?,
            s_hex: row.get(1)?,
            z_hex: row.get(2)?,
        })
    })?;

    let mut sigs_hnp = Vec::new();
    for sig_res in sig_iter {
        let sig_db = sig_res?;
        let s = BigInt::from_str_radix(&sig_db.s_hex, 16).unwrap_or_default();
        if s.is_zero() { continue; }

        let s_inv = s.extended_gcd(&p_bi).x;
        let r = BigInt::from_str_radix(&sig_db.r_hex, 16).unwrap_or_default();
        let z = BigInt::from_str_radix(&sig_db.z_hex, 16).unwrap_or_default();
        
        let t = (&r * &s_inv).mod_floor(&p_bi);
        let u = (&z * &s_inv).mod_floor(&p_bi);
        sigs_hnp.push(SigHnp { t, u });
    }

    if sigs_hnp.len() > 16 { // Need enough data for spectral analysis
        solve_hnp_bias(&sigs_hnp, fft_size, 10.0)?;
    } else {
        println!("[!] Not enough signatures for address {} to perform bias analysis.", address);
    }

    Ok(())
}
