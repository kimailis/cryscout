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
const MAX_FETCH_PARALLELISM: usize = 1;

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
];

#[derive(Debug, Deserialize)]
struct BlockchainInfoTx {
    hash: String,
    time: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct BlockchainInfoAddr {
    txs: Vec<BlockchainInfoTx>,
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

async fn get_raw_tx_hybrid(rpc: &rpc::BitcoinRpcClient, client: &reqwest::Client, txid: &str) -> Result<String> {
    // 1. Try local RPC first (fastest if available)
    if let Ok(raw) = rpc.get_raw_transaction(txid).await {
        return Ok(raw);
    }

    // 2. Try Esplora APIs (btcscan.org first, then blockstream.info)
    for base in ["https://btcscan.org/api", "https://blockstream.info/api"] {
        let esplora_url = format!("{}/tx/{}/hex", base, txid);
        if let Ok(resp) = client.get(&esplora_url).send().await {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    if !text.is_empty() && text.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Ok(text);
                    }
                }
            }
        }
    }

    // 3. Fallback to blockchain.info
    let url = format!("https://blockchain.info/rawtx/{}?format=hex", txid);
    let resp = client.get(url).send().await?;
    if resp.status().is_success() {
        Ok(resp.text().await?)
    } else {
        Err(anyhow!("Failed to fetch raw tx {} from RPC, blockstream.info, and blockchain.info", txid))
    }
}

async fn fetch_all_prevouts_rpc(rpc: &rpc::BitcoinRpcClient, client: &reqwest::Client, tx: &Transaction) -> Result<Vec<TxOut>> {
    let mut prevouts = Vec::new();
    for vin in &tx.input {
        let prev_tx_hex = get_raw_tx_hybrid(rpc, client, &vin.previous_output.txid.to_string()).await?;
        let prev_tx: Transaction = deserialize(&hex::decode(prev_tx_hex)?)?;
        prevouts.push(prev_tx.output[vin.previous_output.vout as usize].clone());
    }
    Ok(prevouts)
}

async fn get_signature_z_rpc(rpc: &rpc::BitcoinRpcClient, client: &reqwest::Client, tx: &Transaction, vin_idx: usize) -> Result<String> {
    let mut cache = SighashCache::new(tx);
    let vin = &tx.input[vin_idx];
    
    if !vin.witness.is_empty() {
        let prevouts = fetch_all_prevouts_rpc(rpc, client, tx).await?;
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
        let prev_tx_hex = get_raw_tx_hybrid(rpc, client, &vin.previous_output.txid.to_string()).await?;
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

async fn process_transaction(rpc: &rpc::BitcoinRpcClient, client: &reqwest::Client, tx: &Transaction, tracked_addresses: &HashSet<String>, height: Option<u64>) -> Result<usize> {
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
            // Skip non-standard pubkeys (multisig redeem scripts etc.)
            let pk_len = pk_bytes.len();
            if pk_len != 33 && pk_len != 65 { continue; }

            let p2pkh = Address::p2pkh(&pk, Network::Bitcoin).to_string();
            let p2wpkh = Address::p2wpkh(&pk, Network::Bitcoin).map(|a| a.to_string()).ok();
            let p2sh_wpkh = Address::p2shwpkh(&pk, Network::Bitcoin).map(|a| a.to_string()).ok();

            let mut matched_addr = None;
            if tracked_addresses.contains(&p2pkh) {
                matched_addr = Some(p2pkh);
            } else if let Some(ref a) = p2wpkh {
                if tracked_addresses.contains(a) { matched_addr = p2wpkh; }
            }
            if matched_addr.is_none() {
                if let Some(ref a) = p2sh_wpkh {
                    if tracked_addresses.contains(a) { matched_addr = p2sh_wpkh; }
                }
            }

            if let Some(addr) = matched_addr {
                if let Ok(z) = get_signature_z_rpc(rpc, client, tx, vin_idx).await {
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

async fn scan_block(rpc: &rpc::BitcoinRpcClient, client: &reqwest::Client, height: u64, tracked_addresses: &HashSet<String>) -> Result<usize> {
    let hash = rpc.get_block_hash(height).await?;
    let block_hex = rpc.get_block_raw(&hash).await?;
    let block: bitcoin::Block = deserialize(&hex::decode(block_hex)?)?;
    
    let mut total_extracted = 0;
    for tx in &block.txdata {
        total_extracted += process_transaction(rpc, client, tx, tracked_addresses, Some(height)).await?;
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
    if cpu > 70.0 || ram > 90.0 { 1 }
    else if cpu > 60.0 || ram > 85.0 { 2 }
    else if cpu > 50.0 { 4 }
    else { MAX_FETCH_PARALLELISM }
}

async fn throttle_for_system_load(task_state: &Arc<RwLock<String>>) {
    let (cpu, ram) = current_resource_profile();
    let delay = if cpu > 75.0 || ram > 92.0 { Duration::from_secs(12) }
    else if cpu > 60.0 || ram > 85.0 { Duration::from_secs(6) }
    else if cpu > 55.0 { Duration::from_secs(2) }
    else { Duration::from_secs(0) };

    if !delay.is_zero() {
        if let Ok(mut task) = task_state.write() {
            *task = format!("Fetcher throttling for load (CPU {:.1}%, RAM {:.1}%)", cpu, ram);
        }
        sleep(delay).await;
    }
}

/// Fetch TX list for an address. Tries multiple APIs with fallback.
async fn get_address_txids_hybrid(client: &reqwest::Client, address: &str, last_seen_txid: Option<&str>) -> Result<Vec<(String, Option<u64>)>> {
    // Esplora API URLs — try btcscan.org first (fresh, not rate-limited), then blockstream.info
    let esplora_bases = ["https://btcscan.org/api", "https://blockstream.info/api"];
    let mempool_urls: Vec<String> = esplora_bases.iter().map(|base| {
        if let Some(last_txid) = last_seen_txid {
            format!("{}/address/{}/txs/chain/{}", base, address, last_txid)
        } else {
            format!("{}/address/{}/txs", base, address)
        }
    }).collect();

    // Try Esplora APIs (btcscan.org first — fresh endpoint, then blockstream.info)
    for esplora_url in &mempool_urls {
        sleep(Duration::from_millis(3000 + (rand::random::<u64>() % 2000))).await;
        let ua = USER_AGENTS.choose(&mut rand::thread_rng()).unwrap();
        match client.get(esplora_url).header("User-Agent", *ua).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    if let Ok(txs) = resp.json::<Vec<serde_json::Value>>().await {
                        let results: Vec<(String, Option<u64>)> = txs.iter()
                            .filter_map(|tx| {
                                let txid = tx["txid"].as_str()?.to_string();
                                let time = tx["status"]["block_time"].as_u64();
                                Some((txid, time))
                            })
                            .collect();
                        if !results.is_empty() {
                            return Ok(results);
                        }
                    }
                } else if status.as_u16() == 429 {
                    println!("[RATE] {} 429 for {}, trying next API", esplora_url, address);
                    sleep(Duration::from_secs(10)).await;
                }
            }
            Err(_) => {}
        }
    }

    // Fallback: blockchain.info
    sleep(Duration::from_millis(3000 + (rand::random::<u64>() % 2000))).await;
    let ua = USER_AGENTS.choose(&mut rand::thread_rng()).unwrap();
    let url = format!("https://blockchain.info/rawaddr/{}?limit=50&offset=0", address);
    match client.get(&url).header("User-Agent", *ua).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                if let Ok(addr_data) = resp.json::<BlockchainInfoAddr>().await {
                    let results: Vec<(String, Option<u64>)> = addr_data.txs.into_iter()
                        .map(|t| (t.hash, t.time))
                        .collect();
                    if !results.is_empty() {
                        return Ok(results);
                    }
                }
            } else if resp.status().as_u16() == 429 {
                println!("[RATE] blockchain.info 429 for {}, backing off 30s", address);
                sleep(Duration::from_secs(30)).await;
            }
        }
        Err(e) => println!("[DEBUG] blockchain.info failed for {}: {}", address, e),
    }

    Err(anyhow!("All APIs failed for {}", address))
}

/// Returns (extracted_sigs, fetch_complete). fetch_complete is false if API errors interrupted pagination.
async fn analyze_address_hybrid(rpc: &rpc::BitcoinRpcClient, client: Arc<reqwest::Client>, address: String, sem: Arc<Semaphore>) -> Result<(Vec<ExtractedSig>, bool)> {
    let _permit = sem.acquire().await?;
    println!("[INFO] Analyzing address: {}", address);

    let mut all_extracted = Vec::new();

    let mut existing_txids = HashSet::new();
    // Check balance and vulnerability score to set deeper fetching limits
    let (max_sigs, max_pages) = if let Ok(conn) = Connection::open(DB_FILE) {
        let _ = conn.pragma_update(None, "busy_timeout", &30000);
        if let Ok(mut stmt) = conn.prepare("SELECT txid FROM signatures WHERE address = ?1") {
            if let Ok(txs) = stmt.query_map(params![address], |row| row.get::<_, String>(0)) {
                existing_txids = txs.flatten().collect();
            }
        }
        // High-value or high-score addresses get deeper fetching
        let (balance, score): (f64, f64) = conn.query_row(
            "SELECT COALESCE(balance, 0), COALESCE(vulnerability_score, 0) FROM addresses WHERE address = ?1",
            params![address], |r| Ok((r.get(0)?, r.get(1)?))
        ).unwrap_or((0.0, 0.0));

        if balance > 1.0 || score > 5.0 {
            println!("[INFO] High-value target {} (balance={:.4}, score={:.1}): deep fetch mode", address, balance, score);
            (2000usize, 80usize) // Up to 2000 sigs, 80 pages
        } else if balance > 0.1 || score > 2.0 {
            (1000, 40) // Medium-value: moderate fetch
        } else {
            (500, 20) // Default
        }
    } else {
        (500usize, 20usize)
    };

    let mut last_txid: Option<String> = None;
    let mut page = 0;
    let mut fetch_failed = false;

    loop {
        let txs = match get_address_txids_hybrid(&client, &address, last_txid.as_deref()).await {
            Ok(t) => t,
            Err(e) => {
                println!("[WARN] TX list fetch failed for {}: {}", address, e);
                fetch_failed = true;
                break;
            }
        };

        if txs.is_empty() { break; }

        // Remember last txid for pagination (blockstream.info chain pagination)
        last_txid = txs.last().map(|(txid, _)| txid.clone());

        for (txid, time) in &txs {
            if existing_txids.contains(txid) { continue; }

            if let Ok(raw_hex) = get_raw_tx_hybrid(rpc, &client, txid).await {
                if let Ok(tx) = deserialize::<Transaction>(&hex::decode(raw_hex).unwrap_or_default()) {
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
                            // Skip non-standard pubkeys (multisig redeem scripts etc.)
                            let pk_len = pk.to_bytes().len();
                            if pk_len != 33 && pk_len != 65 { continue; }

                            let p2pkh = Address::p2pkh(&pk, Network::Bitcoin).to_string();
                            let p2wpkh = Address::p2wpkh(&pk, Network::Bitcoin).map(|a| a.to_string()).ok();
                            let p2sh_wpkh = Address::p2shwpkh(&pk, Network::Bitcoin).map(|a| a.to_string()).ok();

                            if p2pkh == address || p2wpkh == Some(address.clone()) || p2sh_wpkh == Some(address.clone()) {
                                if let Ok(z) = get_signature_z_rpc(rpc, &client, &tx, vin_idx).await {
                                    let sig_hex = if !vin.witness.is_empty() { hex::encode(&vin.witness[0]) } else { hex::encode(vin.script_sig.as_bytes()) };
                                    if let Some((r, s)) = parse_der(&sig_hex) {
                                        all_extracted.push(ExtractedSig {
                                            r, s, z,
                                            txid: tx.txid().to_string(),
                                            vin: vin_idx as u32,
                                            pubkey: hex::encode(pk.to_bytes()),
                                            timestamp: *time,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        page += 1;
        // Dynamic limits based on target value/score
        if all_extracted.len() > max_sigs || page > max_pages { break; }
        sleep(Duration::from_millis(200)).await;
    }
    Ok((all_extracted, !fetch_failed))
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
        let mut backoff_secs: u64 = 30;
        let max_backoff: u64 = 600; // Cap at 10 minutes between retries
        loop {
            match rpc_clone.get_block_count().await {
                Ok(current_height) => {
                    backoff_secs = 30; // Reset backoff on success
                    if let Ok(conn) = Connection::open(DB_FILE) {
                        let _ = conn.pragma_update(None, "busy_timeout", &30000);

                        let hist_start = get_global_stat(&conn, "start_historical_block").unwrap_or(None);
                        let hist_end = get_global_stat(&conn, "end_historical_block").unwrap_or(None);

                        if let (Some(start), Some(end)) = (hist_start, hist_end) {
                            if start <= end {
                                println!("[INFO] Performing historical block scan: {} to {}", start, end);
                                let tracked = get_tracked_addresses(&conn).unwrap_or_default();
                                let hist_client = reqwest::Client::new();
                                for h in start..=end {
                                    let _ = scan_block(&rpc_clone, &hist_client, h as u64, &tracked).await;
                                }
                                let _ = conn.execute("DELETE FROM global_stats WHERE key IN ('start_historical_block', 'end_historical_block')", []);
                                sleep(Duration::from_secs(10)).await;
                            }
                        }

                        let last_height = get_global_stat(&conn, "last_scanned_block").unwrap_or(Some(0)).unwrap_or(0);
                        let tracked = get_tracked_addresses(&conn).unwrap_or_default();

                        if current_height > last_height as u64 {
                            let end_height = std::cmp::min(current_height, last_height as u64 + 5);
                            println!("[INFO] Scanning blocks from {} to {} (current tip: {})", last_height + 1, end_height, current_height);
                            let client_inner = reqwest::Client::new();
                            for h in (last_height + 1)..=end_height as i64 {
                                if let Ok(n) = scan_block(&rpc_clone, &client_inner, h as u64, &tracked).await {
                                    if n > 0 { println!("[SUCCESS] Extracted {} sigs from block {}", n, h); }
                                }
                                let _ = set_global_stat(&conn, "last_scanned_block", h);
                            }
                        }
                    }
                }
                Err(_) => {
                    // Exponential backoff: don't spam logs when RPC is unavailable
                    if backoff_secs == 30 {
                        eprintln!("[WARN] RPC unavailable. Backing off (next retry in {}s).", backoff_secs);
                    }
                    backoff_secs = (backoff_secs * 2).min(max_backoff);
                }
            }
            sleep(Duration::from_secs(backoff_secs)).await;
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
            WHERE a.balance > 0
              AND (a.type IS NULL OR a.type NOT LIKE 'P2PK%')
              AND (a.transactions IS NULL OR a.transactions >= 2)
              AND (a.sigs_fetched = 0 OR a.sigs_fetched IS NULL OR (a.transactions > 0 AND COALESCE(s.sig_count, 0) < a.transactions))
            ORDER BY a.sigs_fetched ASC, a.balance DESC, a.vulnerability_score DESC
            LIMIT 20
            ")?;
        
        let addresses: Vec<String> = stmt.query_map([], |row| row.get(0))?.flatten().collect();

        if addresses.is_empty() {
            if let Ok(mut task) = task_state.write() { *task = "Fetcher idle".to_string(); }
            sleep(Duration::from_secs(60)).await;
            continue;
        }

        println!("[START] Found {} target addresses to analyze.", addresses.len());
        if let Ok(mut task) = task_state.write() { *task = format!("Fetching signatures for {} addresses (sequential)", addresses.len()); }

        let client = Arc::new(reqwest::Client::builder().connect_timeout(Duration::from_secs(15)).timeout(Duration::from_secs(45)).build()?);
        let sem = Arc::new(Semaphore::new(1));

        // Process addresses strictly one-at-a-time to respect API rate limits
        let mut total_sigs = 0;
        for addr in addresses {
            let sigs_result = analyze_address_hybrid(&rpc_client, Arc::clone(&client), addr.clone(), Arc::clone(&sem)).await;
            // Mandatory cooldown between addresses
            sleep(Duration::from_secs(5)).await;

            if let Ok((sigs, fetch_complete)) = sigs_result {
                if sigs.is_empty() {
                    if fetch_complete {
                        let conn = Connection::open(DB_FILE)?;
                        let _ = conn.pragma_update(None, "busy_timeout", &30000);
                        // Mark as fetched AND set transactions=1 so we don't re-fetch
                        // (if it had spendable ECDSA sigs, we would have found them)
                        let _ = conn.execute(
                            "UPDATE addresses SET sigs_fetched = 1, transactions = COALESCE(transactions, 1) WHERE address = ?1",
                            params![addr]
                        );
                    } else {
                        println!("[WARN] Fetch incomplete for {} (API errors), will retry later", addr);
                    }
                    continue;
                }
                println!("[SUCCESS] Extracted {} sigs for {}{}", sigs.len(), addr,
                    if fetch_complete { "" } else { " (partial — API errors, will retry)" });
                total_sigs += sigs.len();

                let conn = Connection::open(DB_FILE)?;
                let _ = conn.pragma_update(None, "busy_timeout", &30000);
                for sig in &sigs {
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
                if fetch_complete {
                    // Mark sigs fetched AND reset analyzed + sigs_scanned so the analyzer
                    // re-scores and the striker re-strikes with the new (larger) sig set
                    let _ = conn.execute(
                        "UPDATE addresses SET sigs_fetched = 1, analyzed = 0, sigs_scanned = 0 WHERE address = ?1",
                        params![addr],
                    );
                } else {
                    // Partial fetch: reset analyzed/scanned for new sigs but don't mark as fully fetched
                    let _ = conn.execute(
                        "UPDATE addresses SET analyzed = 0, sigs_scanned = 0 WHERE address = ?1",
                        params![addr],
                    );
                }
            }
        }
        if let Ok(mut task) = task_state.write() { *task = format!("Fetcher sleeping after collecting {} signatures", total_sigs); }
        sleep(Duration::from_secs(60)).await;
    }
}
