use anyhow::Result;
use bitcoin::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::network::constants::Network;
use bitcoin::{Address, PublicKey};
use bitcoin::secp256k1::Secp256k1;
use rusqlite::{params, Connection};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use sysinfo::System;
use bip39::{Mnemonic, MnemonicType, Language, Seed};
use rayon::prelude::*;
use std::io::Write;

const DB_FILE: &str = "cryscout.db";

struct ScouterState {
    targets: RwLock<HashSet<String>>,
    checked_count: AtomicU64,
    start_time: Instant,
    live_sample: RwLock<Option<(String, String)>>,
}

fn load_targets() -> Result<HashSet<String>> {
    let conn = Connection::open(DB_FILE)?;
    let _ = conn.pragma_update(None, "busy_timeout", &30000);
    let mut stmt = conn.prepare("SELECT address FROM addresses")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut targets = HashSet::new();
    for row in rows {
        targets.insert(row?);
    }
    println!("Loaded {} target addresses.", targets.len());
    Ok(targets)
}

fn log_hit(mnemonic: &str, path: &str, address: &str, privkey: &str) -> Result<()> {
    let conn = Connection::open(DB_FILE)?;
    let _ = conn.pragma_update(None, "busy_timeout", &30000);
    conn.execute(
        "INSERT OR IGNORE INTO recovered_keys (address, privkey_hex, method, found_at) VALUES (?1, ?2, ?3, datetime('now'))",
        params![address, privkey, format!("WalletScout: {}", path)],
    )?;
    
    let hit_info = format!("HIT! Address: {}, Path: {}, Mnemonic: {}, PrivKey: {}\n", address, path, mnemonic, privkey);
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open("hits.txt")?;
    file.write_all(hit_info.as_bytes())?;
    
    println!("\n[!!!] {}", hit_info);
    Ok(())
}

fn maybe_throttle_for_system_load() {
    let mut system = System::new_all();
    system.refresh_cpu_usage();
    system.refresh_memory();
    let cpu = system.global_cpu_info().cpu_usage();
    let ram = (system.used_memory() as f64 / system.total_memory() as f64) * 100.0;
    let delay = if cpu > 90.0 || ram > 92.0 {
        Duration::from_secs(8)
    } else if cpu > 80.0 || ram > 85.0 {
        Duration::from_secs(3)
    } else {
        Duration::from_secs(0)
    };

    if !delay.is_zero() {
        std::thread::sleep(delay);
    }
}

fn main() -> Result<()> {
    let _ = rayon::ThreadPoolBuilder::new().num_threads(1).build_global();
    let targets = load_targets()?;
    if targets.is_empty() {
        println!("No targets found. Check addresses table.");
        return Ok(());
    }

    let state = Arc::new(ScouterState {
        targets: RwLock::new(targets),
        checked_count: AtomicU64::new(0),
        start_time: Instant::now(),
        live_sample: RwLock::new(None),
    });

    let state_monitor = Arc::clone(&state);
    std::thread::spawn(move || {
        let mut last_count = 0;
        loop {
            std::thread::sleep(Duration::from_secs(60));
            let current_count = state_monitor.checked_count.load(Ordering::Relaxed);
            let diff = current_count - last_count;
            last_count = current_count;
            let kps = diff as f64 / 60.0;
            let _total_elapsed = state_monitor.start_time.elapsed().as_secs();
            
            let sample_str = if let Ok(sample) = state_monitor.live_sample.read() {
                if let Some((m, a)) = &*sample {
                    format!(" | {} -> {}", m, a)
                } else { "".to_string() }
            } else { "".to_string() };

            match Connection::open(DB_FILE) {
                Ok(conn) => {
                    let task_msg = format!("Scouting ({:.0} kps){}", kps, sample_str);
                    println!("[Scouter] {}", task_msg);
                    let _ = std::io::stdout().flush();
                    let _ = conn.execute(
                        "INSERT OR REPLACE INTO worker_status (worker_id, task, cpu_usage, ram_usage, last_heartbeat)
                         VALUES (?1, ?2, ?3, ?4, datetime('now'))",
                        params![format!("Scouter-{}", std::process::id()), task_msg, 0.0, 0.0],
                    );
                    let _ = conn.execute(
                        "UPDATE global_stats SET value_i = ?1, updated_at = datetime('now') WHERE key = 'scouter_checked'",
                        params![current_count],
                    );
                },
                Err(e) => eprintln!("[Scouter Monitor] DB Error: {}", e),
            }
        }
    });

    let state_refresher = Arc::clone(&state);
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(60));
        match load_targets() {
            Ok(targets) => {
                if let Ok(mut current) = state_refresher.targets.write() {
                    *current = targets;
                }
            }
            Err(e) => eprintln!("[Scouter Refresh] DB Error: {}", e),
        }
    });

    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    let paths = vec![
        "m/44'/0'/0'/0/0",
        "m/49'/0'/0'/0/0",
    ];
    
    let parsed_paths: Vec<(DerivationPath, &str)> = paths.into_iter().map(|p| {
        (p.parse::<DerivationPath>().expect("Valid path"), p)
    }).collect();

    let _ = rayon::ThreadPoolBuilder::new().num_threads(1).build_global();

    loop {
        maybe_throttle_for_system_load();
        (0..1000).into_par_iter().for_each(|_| {
            let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
            let seed = Seed::new(&mnemonic, "");
            let root = ExtendedPrivKey::new_master(network, seed.as_bytes()).unwrap();

            let mut sampled_addr = "".to_string();
            let last_mnemonic = mnemonic.phrase().to_string();

            for (path, path_str) in &parsed_paths {
                let derived = root.derive_priv(&secp, path).unwrap();
                let secret_key = derived.private_key;
                let pubkey = PublicKey::new(secret_key.public_key(&secp));
                
                let address = if path_str.contains("44'") {
                    Address::p2pkh(&pubkey, network)
                } else {
                    Address::p2shwpkh(&pubkey, network).expect("P2SH-WPKH")
                };

                let addr_str = address.to_string();
                
                // Pick an address to show in the UI (prefer Legacy)
                if addr_str.starts_with('1') || (sampled_addr.is_empty() && addr_str.starts_with('3')) {
                    sampled_addr = addr_str.clone();
                }

                let is_target = state
                    .targets
                    .read()
                    .map(|targets| targets.contains(&addr_str))
                    .unwrap_or(false);
                if is_target {
                    let _ = log_hit(mnemonic.phrase(), path_str, &addr_str, &hex::encode(secret_key.secret_bytes()));
                }
            }
            state.checked_count.fetch_add(1, Ordering::Relaxed);
            
            // Periodically update live sample
            if rand::random::<u16>() % 500 == 0 {
                if let Ok(mut sample) = state.live_sample.write() {
                    if sampled_addr.is_empty() { sampled_addr = "bc1q...".to_string(); }
                    *sample = Some((last_mnemonic, sampled_addr));
                }
            }
        });
    }
}
