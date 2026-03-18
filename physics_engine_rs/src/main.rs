use anyhow::Result;
use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero, Signed};
use rustfft::{FftPlanner, num_complex::Complex};
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::Path;
use rusqlite::{params, Connection};

mod chaos_bias;

#[derive(Deserialize)]
struct SigEntry {
    r: String,
    s: Option<String>,
    t: Option<u64>,
}

fn log_vulnerability(address: &str, v_type: &str, severity: &str, details: &str) -> Result<()> {
    let conn = Connection::open("cryscout.db")?;
    conn.busy_timeout(std::time::Duration::from_secs(30))?;
    conn.execute(
        "INSERT OR IGNORE INTO vulnerabilities (address, type, severity, details, found_at) VALUES (?1, ?2, ?3, ?4, datetime('now'))",
        params![address, v_type, severity, details],
    )?;
    Ok(())
}

fn hex_to_bigint(hex_str: &str) -> BigInt {
    let clean = hex_str.trim_start_matches("0x");
    BigInt::parse_bytes(clean.as_bytes(), 16).unwrap_or_default()
}

fn analyze_time_coupling(sigs: &[SigEntry], r_values: &[BigInt]) -> Option<f64> {
    if sigs.len() < 3 { return None; }
    
    let mut delta_ts = Vec::new();
    let mut delta_rs = Vec::new();

    for i in 0..sigs.len() - 1 {
        let t1 = sigs[i].t.unwrap_or(0);
        let t2 = sigs[i+1].t.unwrap_or(0);
        if t1 == 0 || t2 == 0 || t2 <= t1 {
            continue;
        }
        let dt = (t2 - t1) as f64;
        
        let r1 = &r_values[i];
        let r2 = &r_values[i+1];
        let dr = (r2 - r1).abs().to_f64().unwrap_or(0.0);
        
        delta_ts.push(dt);
        delta_rs.push(dr);
    }

    if delta_ts.len() < 3 { return None; }

    let mean_t = delta_ts.iter().sum::<f64>() / delta_ts.len() as f64;
    let mean_r = delta_rs.iter().sum::<f64>() / delta_rs.len() as f64;

    let mut cov = 0.0f64;
    let mut var_t = 0.0f64;
    let mut var_r = 0.0f64;

    for i in 0..delta_ts.len() {
        let diff_t = delta_ts[i] - mean_t;
        let diff_r = delta_rs[i] - mean_r;
        cov += diff_t * diff_r;
        var_t += diff_t * diff_t;
        var_r += diff_r * diff_r;
    }

    if var_t == 0.0 || var_r == 0.0 { return Some(0.0); }

    let corr = cov / (var_t.sqrt() * var_r.sqrt());
    Some(corr.abs())
}

fn analyze_bit_plane_spectra(r_values: &[BigInt]) -> Option<usize> {
    let n = r_values.len();
    if n < 8 { return None; }
    
    let mut planner = FftPlanner::new();
    let fft = planner.plan_fft_forward(n);

    let mut max_peaks = 0;

    for b in 0..16 {
        let mut buffer: Vec<Complex<f64>> = r_values.iter().map(|r| {
            let bit: BigInt = (r >> b) & BigInt::from(1u32);
            let val = if bit.is_zero() { 0.0 } else { 1.0 };
            Complex::new(val, 0.0)
        }).collect();

        fft.process(&mut buffer);

        let mut peak_count = 0;
        let threshold = (n as f64) * 0.4; // Heuristic threshold

        for i in 1..n/2 {
            if buffer[i].norm() > threshold {
                peak_count += 1;
            }
        }
        
        if peak_count > max_peaks {
            max_peaks = peak_count;
        }
    }
    
    Some(max_peaks)
}

fn analyze_differential_pairs(r_values: &[BigInt]) -> Option<f64> {
    if r_values.len() < 4 { return None; }
    
    let mut stable_ratios = 0;
    let total = r_values.len() - 2;

    for i in 0..total {
        let d1 = (&r_values[i+1] - &r_values[i]).abs().to_f64().unwrap_or(0.0);
        let d2 = (&r_values[i+2] - &r_values[i+1]).abs().to_f64().unwrap_or(0.0);
        
        if d1 > 0.0 {
            let ratio = d2 / d1;
            // Check for integer or very simple fractional motifs
            let rounded = ratio.round();
            if (ratio - rounded).abs() < 0.01 && rounded > 0.0 && rounded < 10.0 {
                stable_ratios += 1;
            }
        }
    }

    Some(stable_ratios as f64 / total as f64)
}

fn analyze_signature_drift(sigs: &[SigEntry], r_values: &[BigInt]) -> Option<f64> {
    if sigs.len() < 10 { return None; }
    
    let mut sessions = Vec::new();
    let mut current_session = Vec::new();
    
    for i in 0..sigs.len() {
        if i > 0 {
            let t1 = sigs[i-1].t.unwrap_or(0);
            let t2 = sigs[i].t.unwrap_or(0);
            if t1 > 0 && t2 > 0 && (t2 as i64 - t1 as i64).abs() > 3600 {
                if current_session.len() >= 3 {
                    sessions.push(current_session.clone());
                }
                current_session.clear();
            }
        }
        current_session.push(&r_values[i]);
    }
    if current_session.len() >= 3 {
        sessions.push(current_session);
    }

    if sessions.len() < 2 { return None; }

    let mut session_biases = Vec::new();
    for sess in &sessions {
        let mut lsb_count = 0;
        for r in sess {
            if !((*r).clone() & BigInt::from(1u32)).is_zero() {
                lsb_count += 1;
            }
        }
        session_biases.push(lsb_count as f64 / sess.len() as f64);
    }

    let mean = session_biases.iter().sum::<f64>() / session_biases.len() as f64;
    let var = session_biases.iter().map(|b| (b - mean).powi(2)).sum::<f64>() / session_biases.len() as f64;
    
    if var < 0.001 {
        Some(1.0 - var * 100.0)
    } else {
        Some(0.0)
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <sigs.json>", args[0]);
        return Ok(());
    }

    let file_content = fs::read_to_string(&args[1])?;
    let sigs: Vec<SigEntry> = serde_json::from_str(&file_content).unwrap_or_default();

    if sigs.len() < 3 {
        return Ok(());
    }

    let r_values: Vec<BigInt> = sigs.iter().map(|s| hex_to_bigint(&s.r)).collect();

    let mut flagged = false;
    let mut reasons = Vec::new();

    if let Some(corr) = analyze_time_coupling(&sigs, &r_values) {
        if corr > 0.7 {
            flagged = true;
            reasons.push(format!("Time-Coupled Entropy Collapse (corr={:.2})", corr));
        }
    }

    if let Some(peaks) = analyze_bit_plane_spectra(&r_values) {
        if peaks > 2 {
            flagged = true;
            reasons.push(format!("Bit-Plane Spectral Stack anomalies ({} peaks)", peaks));
        }
    }

    if let Some(ratio) = analyze_differential_pairs(&r_values) {
        if ratio > 0.2 { 
            flagged = true;
            reasons.push(format!("Differential Pair Scoring stable ratios ({:.1}%)", ratio * 100.0));
        }
    }

    if let Some(drift) = analyze_signature_drift(&sigs, &r_values) {
        if drift > 0.8 {
            flagged = true;
            reasons.push(format!("Signature Drift reset pattern detected ({:.2})", drift));
        }
    }

    // Chaos analysis integration
    let analyzer = chaos_bias::ChaosAnalyzer::new_lorenz_standard();
    let mut phase_points = Vec::new();
    
    for i in 0..r_values.len().saturating_sub(2) {
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        let mut k3 = [0u8; 32];
        
        let r1_bytes = r_values[i].to_bytes_be().1;
        let r2_bytes = r_values[i+1].to_bytes_be().1;
        let r3_bytes = r_values[i+2].to_bytes_be().1;
        
        // Pad left with zeros if < 32 bytes
        let copy_padded = |src: &[u8], dst: &mut [u8; 32]| {
            let start = dst.len().saturating_sub(src.len());
            let copy_len = src.len().min(dst.len());
            dst[start..].copy_from_slice(&src[src.len() - copy_len..]);
        };
        
        copy_padded(&r1_bytes, &mut k1);
        copy_padded(&r2_bytes, &mut k2);
        copy_padded(&r3_bytes, &mut k3);

        let point = chaos_bias::ChaosAnalyzer::map_nonces_to_space(&k1, &k2, &k3);
        phase_points.push(point);
    }
    
    if phase_points.len() >= 3 {
        let dim = analyzer.calculate_fractal_dimension(&phase_points);
        if dim < 2.5 {
            flagged = true;
            reasons.push(format!("Low Fractal Dimension (Chaos/Lorenz attractor) detected ({:.2})", dim));
        }
    }

    let filename = Path::new(&args[1]).file_name().unwrap_or_default().to_string_lossy().to_string();
    let address = if filename.starts_with("temp_sigs_") && filename.ends_with(".json") {
        filename[10..filename.len()-5].to_string()
    } else if filename.starts_with("sigs_") && filename.ends_with(".json") {
        filename[5..filename.len()-5].to_string()
    } else {
        filename.clone()
    };

    if flagged {
        println!("[PhysicsEngine] POTENTIAL RNG VULNERABILITY DETECTED for {}", address);
        for r in &reasons {
            println!("- {}", r);
            let parts: Vec<&str> = r.splitn(2, '(').collect();
            let v_type = parts[0].trim();
            let _ = log_vulnerability(&address, v_type, "High", r);
        }
    }

    Ok(())
}
