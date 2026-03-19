use anyhow::{anyhow, Context, Result};
use futures::future::join_all;
use rand::seq::SliceRandom;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use sysinfo::System;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};
use std::collections::HashSet;
use bitcoin::{Transaction, consensus::deserialize, PublicKey, Address, Network, OutPoint, TxOut, ScriptBuf};
use bitcoin::sighash::{SighashCache, EcdsaSighashType};

mod rpc;

const DB_FILE: &str = "cryscout.db";
const HEARTBEAT_SECS: u64 = 60;
const MAX_FETCH_PARALLELISM: usize = 10;

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
];

#[derive(Debug, Deserialize)]
struct MempoolTxStatus {
    block_time: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct MempoolTx {
    txid: String,
    status: MempoolTxStatus,
}

#[derive(Debug, Serialize)]
struct ExtractedSig {
    r: String,
    s: String,
    z: String,
    txid: String,
    vin: u32,
    pubkey: String,
    timestamp: Option<u64>,
}

fn double_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash1 = hasher.finalize();
    let mut hasher = Sha256::new();
    hasher.update(hash1);
    hasher.finalize().to_vec()
}

fn parse_der(sig_hex: &str) -> Option<(String, String)> {
    if sig_hex.len() < 10 { return None; }
    let bytes = hex::decode(sig_hex).ok()?;
    let mut pos = 0;
    while pos < bytes.len() {
        if bytes[pos] == 0x30 && pos + 1 < bytes.len() {
            let len = bytes[pos + 1] as usize;
            if pos + 2 + len <= bytes.len() {
                let sub = &bytes[pos..pos + 2 + len];
                if sub.len() >= 8 && sub[2] == 0x02 {
                    let r_len = sub[3] as usize;
                    if sub.len() >= 6 + r_len && sub[4 + r_len] == 0x02 {
                        let s_len = sub[5 + r_len] as usize;
                        if sub.len() >= 6 + r_len + s_len {
                            let r_bytes = &sub[4..4 + r_len];
                            let s_bytes = &sub[6 + r_len..6 + r_len + s_len];
                            return Some((hex::encode(r_bytes), hex::encode(s_bytes)));
                        }
                    }
                }
            }
        }
        pos += 1;
    }
    None
}

fn get_global_stat(conn: &Connection, key: &str) -> Result<Option<i64>> {
    let mut stmt = conn.prepare("SELECT value_i FROM global_stats WHERE key = ?1")?;
    let val: Option<i64> = stmt.query_row(params![key], |row| row.get(0)).ok();
    Ok(val)
}

fn set_global_stat(conn: &Connection, key: &str, val: i64) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO global_stats (key, value_i, updated_at) VALUES (?1, ?2, datetime('now'))",
        params![key, val],
    )?;
    Ok(())
}

fn get_tracked_addresses(conn: &Connection) -> Result<HashSet<String>> {
    let mut stmt = conn.prepare("SELECT address FROM addresses")?;
    let addrs: Vec<String> = stmt.query_map([], |row| row.get(0))?.flatten().collect();
    Ok(addrs.into_iter().collect())
}

async fn fetch_all_prevouts_rpc(rpc: &rpc::BitcoinRpcClient, tx: &Transaction) -> Result<Vec<TxOut>> {
    let mut prevouts = Vec::new();
    for vin in &tx.input {
        let prev_tx_hex = rpc.get_raw_transaction(&vin.previous_output.txid.to_string()).await?;
        let prev_tx: Transaction = deserialize(&hex::decode(prev_tx_hex)?)?;
        prevouts.push(prev_tx.output[vin.previous_output.vout as usize].clone());
    }
    Ok(prevouts)
}

async fn get_signature_z_rpc(rpc: &rpc::BitcoinRpcClient, tx: &Transaction, vin_idx: usize) -> Result<String> {
    let mut cache = SighashCache::new(tx);
    let vin = &tx.input[vin_idx];
    
    if !vin.witness.is_empty() {
        let prevouts = fetch_all_prevouts_rpc(rpc, tx).await?;
        let prevout = &prevouts[vin_idx];
        let script_code = if prevout.script_pubkey.is_v0_p2wpkh() {
            let pkh = &prevout.script_pubkey.as_bytes()[2..22];
            bitcoin::ScriptBuf::builder()
                .push_opcode(bitcoin::opcodes::all::OP_DUP)
                .push_opcode(bitcoin::opcodes::all::OP_HASH160)
                .push_slice(<&bitcoin::script::PushBytes>::try_from(pkh).unwrap())
                .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
                .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
                .into_script()
        } else {
            prevout.script_pubkey.clone()
        };
        
        let hash = cache.segwit_signature_hash(
            vin_idx,
            &script_code,
            prevout.value,
            EcdsaSighashType::All,
        )?;
        Ok(hex::encode(hash))
    } else {
        let prev_tx_hex = rpc.get_raw_transaction(&vin.previous_output.txid.to_string()).await?;
        let prev_tx: Transaction = deserialize(&hex::decode(prev_tx_hex)?)?;
        let script_pubkey = &prev_tx.output[vin.previous_output.vout as usize].script_pubkey;
        
        let hash = cache.legacy_signature_hash(
            vin_idx,
            script_pubkey,
            1, // SIGHASH_ALL
        )?;
        Ok(hex::encode(hash))
    }
}

async fn process_transaction(rpc: &rpc::BitcoinRpcClient, tx: &Transaction, tracked_addresses: &HashSet<String>, height: Option<u64>) -> Result<usize> {
    let mut total_extracted = 0;
    for (vin_idx, vin) in tx.input.iter().enumerate() {
        let mut pubkey = None;
        if !vin.witness.is_empty() {
            if let Some(pk_bytes) = vin.witness.last() {
                if let Ok(pk) = PublicKey::from_slice(pk_bytes) { pubkey = Some(pk); }
            }
        } else if !vin.script_sig.is_empty() {
            let bytes = vin.script_sig.as_bytes();
            if bytes.len() >= 34 {
                let pk_len = bytes[bytes.len() - 34] as usize;
                if pk_len == 33 {
                    if let Ok(pk) = PublicKey::from_slice(&bytes[bytes.len() - 33..]) { pubkey = Some(pk); }
                } else if bytes.len() >= 66 {
                    let pk_len = bytes[bytes.len() - 66] as usize;
                    if pk_len == 65 {
                        if let Ok(pk) = PublicKey::from_slice(&bytes[bytes.len() - 65..]) { pubkey = Some(pk); }
                    }
                }
            }
        }

        if let Some(pk) = pubkey {
            let pk_bytes = pk.to_bytes();
            let p2pkh = Address::p2pkh(&pk, Network::Bitcoin).to_string();
            let p2wpkh = Address::p2wpkh(&pk, Network::Bitcoin).map(|a| a.to_string()).ok();
            let p2sh_wpkh = Address::p2shwpkh(&pk, Network::Bitcoin).map(|a| a.to_string()).ok();

            let mut matched_addr = None;
            if tracked_addresses.contains(&p2pkh) { matched_addr = Some(p2pkh); }
            else if let Some(a) = p2wpkh { if tracked_addresses.contains(&a) { matched_addr = Some(a); } }
            else if let Some(a) = p2sh_wpkh { if tracked_addresses.contains(&a) { matched_addr = Some(a); } }

            if let Some(addr) = matched_addr {
                if let Ok(z) = get_signature_z_rpc(rpc, tx, vin_idx).await {
                    let sig_hex = if !vin.witness.is_empty() {
                        hex::encode(&vin.witness[0])
                    } else {
                        hex::encode(vin.script_sig.as_bytes())
                    };

                    if let Some((r, s)) = parse_der(&sig_hex) {
                        use num_bigint::BigInt;
                        use num_traits::Num;
                        let r_int = BigInt::from_str_radix(&r, 16).unwrap_or_default().to_str_radix(10);
                        let s_int = BigInt::from_str_radix(&s, 16).unwrap_or_default().to_str_radix(10);
                        let z_int = BigInt::from_str_radix(&z, 16).unwrap_or_default().to_str_radix(10);
                        
                        if let Ok(conn) = Connection::open(DB_FILE) {
                            let _ = conn.pragma_update(None, "busy_timeout", &30000);
                            let _ = conn.execute(
                                "INSERT OR IGNORE INTO signatures (address, r_hex, s_hex, z_hex, r_int, s_int, z_int, txid, vin, pubkey_hex, block_height) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                                params![addr, r, s, z, r_int, s_int, z_int, tx.txid().to_string(), vin_idx as u32, hex::encode(pk_bytes), height.map(|h| h as i64)],
                            );
                            total_extracted += 1;
                        }
                    }
                }
            }
        }
    }
    Ok(total_extracted)
}

async fn scan_block(rpc: &rpc::BitcoinRpcClient, height: u64, tracked_addresses: &HashSet<String>) -> Result<usize> {
    let hash = rpc.get_block_hash(height).await?;
    let block_hex = rpc.get_block_raw(&hash).await?;
    let block: bitcoin::Block = deserialize(&hex::decode(block_hex)?)?;
    
    let mut total_extracted = 0;
    for tx in &block.txdata {
        total_extracted += process_transaction(rpc, tx, tracked_addresses, Some(height)).await?;
    }
    Ok(total_extracted)
}

fn update_worker_status(task: &str) {
    if let Ok(conn) = Connection::open(DB_FILE) {
        let _ = conn.pragma_update(None, "busy_timeout", &30000);
        let _ = conn.execute(
            "INSERT OR REPLACE INTO worker_status (worker_id, task, cpu_usage, ram_usage, last_heartbeat)
             VALUES (?1, ?2, ?3, ?4, datetime('now'))",
            params![format!("Fetcher-{}", std::process::id()), task, 0.0, 0.0],
        );
    }
}

fn current_resource_profile() -> (f32, f64) {
    let mut system = System::new_all();
    system.refresh_cpu_usage();
    system.refresh_memory();
    let cpu = system.global_cpu_info().cpu_usage();
    let ram = (system.used_memory() as f64 / system.total_memory() as f64) * 100.0;
    (cpu, ram)
}

fn recommended_fetch_parallelism() -> usize {
    let (cpu, ram) = current_resource_profile();
    if cpu > 85.0 || ram > 90.0 { 2 }
    else if cpu > 70.0 || ram > 80.0 { 4 }
    else { MAX_FETCH_PARALLELISM }
}

async fn throttle_for_system_load(task_state: &Arc<RwLock<String>>) {
    let (cpu, ram) = current_resource_profile();
    let delay = if cpu > 90.0 || ram > 92.0 { Duration::from_secs(10) }
    else if cpu > 80.0 || ram > 85.0 { Duration::from_secs(4) }
    else { Duration::from_secs(0) };

    if !delay.is_zero() {
        if let Ok(mut task) = task_state.write() {
            *task = format!("Fetcher throttling for load (CPU {:.1}%, RAM {:.1}%)", cpu, ram);
        }
        sleep(delay).await;
    }
}

async fn analyze_address_hybrid(rpc: &rpc::BitcoinRpcClient, client: Arc<reqwest::Client>, address: String, sem: Arc<Semaphore>) -> Result<Vec<ExtractedSig>> {
    let _permit = sem.acquire().await?;
    println!("[INFO] Analyzing address (Hybrid): {}", address);

    let mut all_extracted = Vec::new();
    let mut last_txid = None;
    let mut consecutive_errors = 0u8;

    let mut existing_txids = HashSet::new();
    if let Ok(conn) = Connection::open(DB_FILE) {
        let _ = conn.pragma_update(None, "busy_timeout", &30000);
        if let Ok(mut stmt) = conn.prepare("SELECT txid FROM signatures WHERE address = ?1") {
            if let Ok(txs) = stmt.query_map(params![address], |row| row.get::<_, String>(0)) {
                existing_txids = txs.flatten().collect();
            }
        }
    }
    
    loop {
        let url = if let Some(txid) = &last_txid {
            format!("https://mempool.space/api/address/{}/txs/chain/{}", address, txid)
        } else {
            format!("https://mempool.space/api/address/{}/txs/chain", address)
        };
        
        let ua = USER_AGENTS.choose(&mut rand::thread_rng()).unwrap();
        let resp = client.get(url).header("User-Agent", *ua).send().await?;
        if !resp.status().is_success() {
            if resp.status().as_u16() == 429 { sleep(Duration::from_secs(10)).await; continue; }
            if resp.status().is_server_error() && consecutive_errors < 5 {
                consecutive_errors += 1;
                sleep(Duration::from_secs(5 * consecutive_errors as u64)).await;
                continue;
            }
            return Err(anyhow!("address fetch failed for {} with status {}", address, resp.status()));
        }
        consecutive_errors = 0;
        let txs = resp.json::<Vec<MempoolTx>>().await?;
        if txs.is_empty() { break; }
        
        last_txid = txs.last().map(|t| t.txid.clone());

        for tx_meta in txs {
            if existing_txids.contains(&tx_meta.txid) { continue; }

            if let Ok(raw_hex) = rpc.get_raw_transaction(&tx_meta.txid).await {
                if let Ok(tx) = deserialize::<Transaction>(&hex::decode(raw_hex).unwrap_or_default()) {
                    for (vin_idx, vin) in tx.input.iter().enumerate() {
                        let prev_tx_hex = rpc.get_raw_transaction(&vin.previous_output.txid.to_string()).await?;
                        let prev_tx: Transaction = deserialize(&hex::decode(prev_tx_hex)?)?;
                        let prevout = &prev_tx.output[vin.previous_output.vout as usize];
                        
                        let mut pubkey = None;
                        if !vin.witness.is_empty() {
                            if let Some(pk_bytes) = vin.witness.last() {
                                if let Ok(pk) = PublicKey::from_slice(pk_bytes) { pubkey = Some(pk); }
                            }
                        } else if !vin.script_sig.is_empty() {
                            let bytes = vin.script_sig.as_bytes();
                            if bytes.len() >= 34 {
                                let pk_len = bytes[bytes.len() - 34] as usize;
                                if pk_len == 33 {
                                    if let Ok(pk) = PublicKey::from_slice(&bytes[bytes.len() - 33..]) { pubkey = Some(pk); }
                                } else if bytes.len() >= 66 {
                                    let pk_len = bytes[bytes.len() - 66] as usize;
                                    if pk_len == 65 {
                                        if let Ok(pk) = PublicKey::from_slice(&bytes[bytes.len() - 65..]) { pubkey = Some(pk); }
                                    }
                                }
                            }
                        }

                        if let Some(pk) = pubkey {
                            let p2pkh = Address::p2pkh(&pk, Network::Bitcoin).to_string();
                            let p2wpkh = Address::p2wpkh(&pk, Network::Bitcoin).map(|a| a.to_string()).ok();
                            let p2sh_wpkh = Address::p2shwpkh(&pk, Network::Bitcoin).map(|a| a.to_string()).ok();

                            if p2pkh == address || p2wpkh == Some(address.clone()) || p2sh_wpkh == Some(address.clone()) {
                                if let Ok(z) = get_signature_z_rpc(rpc, &tx, vin_idx).await {
                                    let sig_hex = if !vin.witness.is_empty() { hex::encode(&vin.witness[0]) } else { hex::encode(vin.script_sig.as_bytes()) };
                                    if let Some((r, s)) = parse_der(&sig_hex) {
                                        all_extracted.push(ExtractedSig {
                                            r, s, z,
                                            txid: tx.txid().to_string(),
                                            vin: vin_idx as u32,
                                            pubkey: hex::encode(pk.to_bytes()),
                                            timestamp: tx_meta.status.block_time,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if all_extracted.len() > 1000 { break; }
        sleep(Duration::from_millis(200)).await;
    }
    Ok(all_extracted)
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("[START] Address Analyzer Service started.");
    
    let rpc_url = std::env::var("BITCOIN_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8332".to_string());
    let rpc_user = std::env::var("BITCOIN_RPC_USER").ok();
    let rpc_pass = std::env::var("BITCOIN_RPC_PASS").ok();
    let rpc_client = Arc::new(rpc::BitcoinRpcClient::new(rpc_url, rpc_user, rpc_pass));

    let rpc_clone = Arc::clone(&rpc_client);
    tokio::spawn(async move {
        println!("[START] RPC Block Scanner Loop started.");
        loop {
            match rpc_clone.get_block_count().await {
                Ok(current_height) => {
                    if let Ok(conn) = Connection::open(DB_FILE) {
                        let _ = conn.pragma_update(None, "busy_timeout", &30000);
                        
                        let hist_start = get_global_stat(&conn, "start_historical_block").unwrap_or(None);
                        let hist_end = get_global_stat(&conn, "end_historical_block").unwrap_or(None);
                        
                        if let (Some(start), Some(end)) = (hist_start, hist_end) {
                            if start <= end {
                                println!("[INFO] Performing historical block scan: {} to {}", start, end);
                                let tracked = get_tracked_addresses(&conn).unwrap_or_default();
                                for h in start..=end {
                                    let _ = scan_block(&rpc_clone, h as u64, &tracked).await;
                                }
                                let _ = conn.execute("DELETE FROM global_stats WHERE key IN ('start_historical_block', 'end_historical_block')", []);
                            }
                        }

                        let last_height = get_global_stat(&conn, "last_scanned_block").unwrap_or(Some(0)).unwrap_or(0);
                        let tracked = get_tracked_addresses(&conn).unwrap_or_default();

                        if current_height > last_height as u64 {
                            let end_height = std::cmp::min(current_height, last_height as u64 + 5);
                            println!("[INFO] Scanning blocks from {} to {} (current tip: {})", last_height + 1, end_height, current_height);
                            for h in (last_height + 1)..=end_height as i64 {
                                if let Ok(n) = scan_block(&rpc_clone, h as u64, &tracked).await {
                                    if n > 0 { println!("[SUCCESS] Extracted {} sigs from block {}", n, h); }
                                }
                                let _ = set_global_stat(&conn, "last_scanned_block", h);
                            }
                        }
                    }
                }
                Err(e) => eprintln!("[WARN] RPC block count check failed: {}. RPC may be unavailable.", e),
            }
            sleep(Duration::from_secs(30)).await;
        }
    });

    let task_state = Arc::new(RwLock::new("Fetcher idle".to_string()));
    let task_state_heartbeat = Arc::clone(&task_state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(HEARTBEAT_SECS));
        loop {
            interval.tick().await;
            let task = task_state_heartbeat.read().map(|s| s.clone()).unwrap_or_else(|_| "Fetcher heartbeat unavailable".to_string());
            update_worker_status(&task);
        }
    });
    
    loop {
        throttle_for_system_load(&task_state).await;
        let conn = Connection::open(DB_FILE)?;
        let _ = conn.pragma_update(None, "busy_timeout", &30000);
        
        let mut stmt = conn.prepare("
            SELECT a.address FROM addresses a
            LEFT JOIN (SELECT address, count(*) as sig_count FROM signatures GROUP BY address) s 
            ON a.address = s.address
            WHERE (a.status = 'Spent/Active' 
            OR a.potential_weakness != 'None Identified'
            OR a.label = 'Lattice Target'
            OR a.status = 'Target'
            OR a.transactions > 0)
            AND (a.sigs_fetched = 0 OR a.sigs_fetched IS NULL OR (a.transactions > 0 AND COALESCE(s.sig_count, 0) < a.transactions))
            ORDER BY a.transactions DESC, a.balance DESC
            LIMIT 50
            ")?;
        
        let addresses: Vec<String> = stmt.query_map([], |row| row.get(0))?.flatten().collect();

        if addresses.is_empty() {
            if let Ok(mut task) = task_state.write() { *task = "Fetcher idle".to_string(); }
            sleep(Duration::from_secs(60)).await;
            continue;
        }

        println!("[START] Found {} target addresses to analyze.", addresses.len());
        if let Ok(mut task) = task_state.write() { *task = format!("Fetching signatures for {} addresses", addresses.len()); }

        let client = Arc::new(reqwest::Client::builder().connect_timeout(Duration::from_secs(10)).timeout(Duration::from_secs(30)).build()?);
        let parallelism = recommended_fetch_parallelism();
        if let Ok(mut task) = task_state.write() { *task = format!("Fetching signatures for {} addresses (parallelism {})", addresses.len(), parallelism); }
        let sem = Arc::new(Semaphore::new(parallelism));
        
        let mut tasks = Vec::new();
        for addr in addresses {
            let c = Arc::clone(&client);
            let s = Arc::clone(&sem);
            let r = Arc::clone(&rpc_client);
            tasks.push(tokio::spawn(async move { (addr.clone(), analyze_address_hybrid(&r, c, addr, s).await) }));
        }

        let results = join_all(tasks).await;
        
        let mut total_sigs = 0;
        for res in results {
            if let Ok((addr, Ok(sigs))) = res {
                if sigs.is_empty() {
                    let conn = Connection::open(DB_FILE)?;
                    let _ = conn.pragma_update(None, "busy_timeout", &30000);
                    let _ = conn.execute("UPDATE addresses SET sigs_fetched = 1 WHERE address = ?1", params![addr]);
                    continue;
                }
                println!("[SUCCESS] Extracted {} sigs for {}", sigs.len(), addr);
                total_sigs += sigs.len();
                
                let conn = Connection::open(DB_FILE)?;
                let _ = conn.pragma_update(None, "busy_timeout", &30000);
                for sig in sigs {
                    use num_bigint::BigInt;
                    use num_traits::Num;
                    let r_int = BigInt::from_str_radix(&sig.r, 16).unwrap_or_default().to_str_radix(10);
                    let s_int = BigInt::from_str_radix(&sig.s, 16).unwrap_or_default().to_str_radix(10);
                    let z_int = BigInt::from_str_radix(&sig.z, 16).unwrap_or_default().to_str_radix(10);
                    
                    let _ = conn.execute(
                        "INSERT OR IGNORE INTO signatures (address, r_hex, s_hex, z_hex, r_int, s_int, z_int, txid, vin, pubkey_hex, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                        params![addr, sig.r, sig.s, sig.z, r_int, s_int, z_int, sig.txid, sig.vin, sig.pubkey, sig.timestamp],
                    );
                }
                let _ = conn.execute("UPDATE addresses SET sigs_fetched = 1 WHERE address = ?1", params![addr]);
            }
        }
        if let Ok(mut task) = task_state.write() { *task = format!("Fetcher sleeping after collecting {} signatures", total_sigs); }
        sleep(Duration::from_secs(60)).await;
    }
}
