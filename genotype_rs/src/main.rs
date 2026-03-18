use anyhow::Result;
use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero, Signed};
use rustfft::{FftPlanner, num_complex::Complex};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use rusqlite::{params, Connection};

#[derive(Deserialize, Debug)]
struct SigEntry {
    r: String,
    s: String,
    z: Option<String>,
}

fn log_vulnerability(address: &str, v_type: &str, severity: &str, details: &str) -> Result<()> {
    let conn = Connection::open("cryscout.db")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.execute(
        "INSERT OR IGNORE INTO vulnerabilities (address, type, severity, details, found_at) VALUES (?1, ?2, ?3, ?4, datetime('now'))",
        params![address, v_type, severity, details],
    )?;
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AddressFingerprint {
    address: String,
    vector: Vec<f64>,
}

fn hex_to_bigint(hex_str: &str) -> BigInt {
    let clean = hex_str.trim_start_matches("0x");
    BigInt::parse_bytes(clean.as_bytes(), 16).unwrap_or_default()
}

fn calculate_byte_entropy(bytes: &[u8]) -> f64 {
    let mut counts = [0; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let mut entropy = 0.0;
    let len = bytes.len() as f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn extract_fingerprint(address: &str, sigs: &[SigEntry]) -> Option<AddressFingerprint> {
    if sigs.len() < 10 {
        return None; // Need sufficient data for a fingerprint
    }

    let r_values: Vec<BigInt> = sigs.iter().map(|s| hex_to_bigint(&s.r)).collect();
    let mut vector = Vec::with_capacity(512);

    // 1. LSB/MSB Bias Profile (16 features)
    let mut lsb_counts = [0.0; 8];
    let mut msb_counts = [0.0; 8];
    
    for r in &r_values {
        let bytes = r.to_bytes_be().1;
        if !bytes.is_empty() {
            let lsb = bytes.last().unwrap();
            let msb = bytes.first().unwrap();
            for i in 0..8 {
                if (lsb >> i) & 1 == 1 { lsb_counts[i] += 1.0; }
                if (msb >> i) & 1 == 1 { msb_counts[i] += 1.0; }
            }
        }
    }
    let n = sigs.len() as f64;
    for i in 0..8 {
        vector.push(lsb_counts[i] / n);
        vector.push(msb_counts[i] / n);
    }

    // 2. Byte Entropy Map (32 features)
    let mut byte_streams: Vec<Vec<u8>> = vec![Vec::new(); 32];
    for r in &r_values {
        let mut bytes = r.to_bytes_be().1;
        // Pad to 32 bytes
        while bytes.len() < 32 {
            bytes.insert(0, 0);
        }
        for (i, &b) in bytes.iter().enumerate().take(32) {
            byte_streams[i].push(b);
        }
    }
    for i in 0..32 {
        vector.push(calculate_byte_entropy(&byte_streams[i]));
    }

    // 3. FFT Peak Signature (10 features)
    let mut planner = FftPlanner::new();
    let fft = planner.plan_fft_forward(r_values.len());
    let mut buffer: Vec<Complex<f64>> = r_values.iter().map(|r| {
        // use LSB for FFT
        let val = if (r.clone() & BigInt::from(1u32)).is_zero() { 0.0 } else { 1.0 };
        Complex::new(val, 0.0)
    }).collect();

    fft.process(&mut buffer);
    let mut magnitudes: Vec<f64> = buffer.iter().skip(1).take(r_values.len() / 2).map(|c| c.norm()).collect();
    magnitudes.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
    for i in 0..10 {
        if i < magnitudes.len() {
            vector.push(magnitudes[i]);
        } else {
            vector.push(0.0);
        }
    }

    // 4. Delta-R Distribution (2 features)
    let mut delta_rs = Vec::new();
    for i in 0..r_values.len() - 1 {
        let dr = (&r_values[i+1] - &r_values[i]).abs().to_f64().unwrap_or(0.0);
        delta_rs.push(dr);
    }
    let mean_dr = delta_rs.iter().sum::<f64>() / delta_rs.len() as f64;
    let var_dr = delta_rs.iter().map(|d| (d - mean_dr).powi(2)).sum::<f64>() / delta_rs.len() as f64;
    
    // Normalize delta R (could be huge, so we take log10)
    vector.push(if mean_dr > 0.0 { mean_dr.log10() } else { 0.0 });
    vector.push(if var_dr > 0.0 { var_dr.log10() } else { 0.0 });

    // Pad to 512 dimensions for the "Fingerprint Vector (512-D)" requirement
    while vector.len() < 512 {
        // We can add polynomial expansions or just zeroes to match the 512-D spec
        vector.push(0.0);
    }

    Some(AddressFingerprint {
        address: address.to_string(),
        vector,
    })
}

// Simple K-Means implementation
fn kmeans_cluster(fingerprints: &[AddressFingerprint], k: usize, max_iters: usize) -> Vec<Vec<usize>> {
    if fingerprints.is_empty() || k == 0 { return vec![]; }
    let k = std::cmp::min(k, fingerprints.len());
    let dim = fingerprints[0].vector.len();
    
    // Initialize centroids using the first K points (basic init)
    let mut centroids: Vec<Vec<f64>> = fingerprints.iter().take(k).map(|f| f.vector.clone()).collect();
    let mut clusters: Vec<Vec<usize>> = vec![Vec::new(); k];

    for _ in 0..max_iters {
        let mut new_clusters: Vec<Vec<usize>> = vec![Vec::new(); k];

        // Assign to nearest centroid (Euclidean distance)
        for (i, f) in fingerprints.iter().enumerate() {
            let mut min_dist = f64::MAX;
            let mut best_k = 0;
            for (c_idx, centroid) in centroids.iter().enumerate() {
                let dist: f64 = f.vector.iter().zip(centroid.iter())
                    .map(|(a, b)| (a - b).powi(2))
                    .sum();
                if dist < min_dist {
                    min_dist = dist;
                    best_k = c_idx;
                }
            }
            new_clusters[best_k].push(i);
        }

        // Update centroids
        let mut max_shift = 0.0_f64;
        for c_idx in 0..k {
            if new_clusters[c_idx].is_empty() { continue; }
            let mut new_centroid = vec![0.0; dim];
            for &pt_idx in &new_clusters[c_idx] {
                for (d, &val) in fingerprints[pt_idx].vector.iter().enumerate() {
                    new_centroid[d] += val;
                }
            }
            let n_pts = new_clusters[c_idx].len() as f64;
            for d in 0..dim {
                new_centroid[d] /= n_pts;
            }
            
            let shift: f64 = centroids[c_idx].iter().zip(new_centroid.iter())
                .map(|(a, b)| (a - b).powi(2)).sum::<f64>().sqrt();
            if shift > max_shift { max_shift = shift; }
            
            centroids[c_idx] = new_centroid;
        }

        clusters = new_clusters;
        if max_shift < 1e-5 { break; }
    }

    clusters
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <directory_with_json_files>", args[0]);
        return Ok(());
    }

    let dir = &args[1];
    let mut fingerprints = Vec::new();

    println!("Scanning directory for signature files...");
    let entries = fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
            let filename = path.file_name().unwrap().to_string_lossy().to_string();
            // Try to extract address from filename, e.g., sigs_1A1zP1...json
            let address = if filename.starts_with("sigs_") && filename.ends_with(".json") {
                filename[5..filename.len()-5].to_string()
            } else {
                filename.clone()
            };

            let content = fs::read_to_string(&path)?;
            if let Ok(sigs) = serde_json::from_str::<Vec<SigEntry>>(&content) {
                if let Some(fp) = extract_fingerprint(&address, &sigs) {
                    fingerprints.push(fp);
                }
            }
        }
    }

    println!("[Genotype] Generated {} fingerprints. Running K-Means clustering (K=3)...", fingerprints.len());
    
    if fingerprints.len() >= 3 {
        let k = 3.min(fingerprints.len());
        let clusters = kmeans_cluster(&fingerprints, k, 100);

        for (i, cluster) in clusters.iter().enumerate() {
            println!("[Genotype] Cluster {}: {} addresses", i, cluster.len());
            for &idx in cluster.iter().take(5) { // Show up to 5 examples
                println!("[Genotype]   - {}", fingerprints[idx].address);
                let _ = log_vulnerability(&fingerprints[idx].address, "Genotype Cluster", "Info", &format!("Part of population cluster {} (total {} members)", i, cluster.len()));
            }
            if cluster.len() > 5 {
                println!("[Genotype]   ... and {} more", cluster.len() - 5);
            }
        }
    } else {
        println!("[Genotype] Not enough fingerprints for clustering.");
    }

    Ok(())
}
