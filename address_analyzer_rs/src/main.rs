use anyhow::{anyhow, Context, Result};
use futures::future::join_all;
use rand::seq::SliceRandom;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};

const DB_FILE: &str = "cryscout.db";

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
];

#[derive(Debug, Deserialize)]
struct MempoolTxStatus {
    confirmed: bool,
    block_height: Option<u32>,
    block_hash: Option<String>,
    block_time: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct MempoolTx {
    txid: String,
    vin: Vec<MempoolVin>,
    vout: Vec<MempoolVout>,
    status: MempoolTxStatus,
    version: u32,
    locktime: u32,
}

#[derive(Debug, Deserialize)]
struct MempoolVin {
    txid: String,
    vout: u32,
    prevout: Option<MempoolVout>,
    scriptsig: Option<String>,
    witness: Option<Vec<String>>,
    sequence: u32,
    scriptsig_asm: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MempoolVout {
    scriptpubkey: String,
    scriptpubkey_address: Option<String>,
    scriptpubkey_type: String,
    value: u64,
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

fn get_varint_bytes(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut b = vec![0xfd];
        b.extend(&(n as u16).to_le_bytes());
        b
    } else if n <= 0xffffffff {
        let mut b = vec![0xfe];
        b.extend(&(n as u32).to_le_bytes());
        b
    } else {
        let mut b = vec![0xff];
        b.extend(&n.to_le_bytes());
        b
    }
}

fn get_real_z_legacy(tx: &MempoolTx, vin_index: usize) -> Result<String> {
    let mut builder = Vec::new();
    builder.extend(&tx.version.to_le_bytes());
    builder.extend(get_varint_bytes(tx.vin.len() as u64));
    
    for (i, vin) in tx.vin.iter().enumerate() {
        let mut txid_bytes = hex::decode(&vin.txid)?;
        txid_bytes.reverse();
        builder.extend(txid_bytes);
        builder.extend(&vin.vout.to_le_bytes());
        
        if i == vin_index {
            let prevout = vin.prevout.as_ref().context("No prevout for legacy z calculation")?;
            let script_bytes = hex::decode(&prevout.scriptpubkey)?;
            builder.extend(get_varint_bytes(script_bytes.len() as u64));
            builder.extend(script_bytes);
        } else {
            builder.push(0);
        }
        builder.extend(&vin.sequence.to_le_bytes());
    }

    builder.extend(get_varint_bytes(tx.vout.len() as u64));
    for vout in &tx.vout {
        builder.extend(&vout.value.to_le_bytes());
        let script_bytes = hex::decode(&vout.scriptpubkey)?;
        builder.extend(get_varint_bytes(script_bytes.len() as u64));
        builder.extend(script_bytes);
    }
    
    builder.extend(&tx.locktime.to_le_bytes());
    builder.extend(&1u32.to_le_bytes()); // SIGHASH_ALL

    Ok(hex::encode(double_sha256(&builder)))
}

fn get_real_z_segwit(tx: &MempoolTx, vin_index: usize) -> Result<String> {
    let mut version = tx.version.to_le_bytes().to_vec();
    
    let mut prevouts_raw = Vec::new();
    for vin in &tx.vin {
        let mut txid_bytes = hex::decode(&vin.txid)?;
        txid_bytes.reverse();
        prevouts_raw.extend(txid_bytes);
        prevouts_raw.extend(&vin.vout.to_le_bytes());
    }
    let hash_prevouts = double_sha256(&prevouts_raw);

    let mut sequence_raw = Vec::new();
    for vin in &tx.vin {
        sequence_raw.extend(&vin.sequence.to_le_bytes());
    }
    let hash_sequence = double_sha256(&sequence_raw);

    let target_vin = &tx.vin[vin_index];
    let mut outpoint = hex::decode(&target_vin.txid)?;
    outpoint.reverse();
    outpoint.extend(&target_vin.vout.to_le_bytes());

    let prevout = target_vin.prevout.as_ref().context("No prevout for segwit z calculation")?;
    
    // Calculate script_code based on type
    let script_code = if prevout.scriptpubkey_type == "v0_p2wsh" {
        // For P2WSH, the script_code is the witness script itself with varint length
        let witness = target_vin.witness.as_ref().context("No witness for P2WSH")?;
        let witness_script_hex = witness.last().context("Empty witness for P2WSH")?;
        let witness_script = hex::decode(witness_script_hex)?;
        let mut sc = get_varint_bytes(witness_script.len() as u64);
        sc.extend(witness_script);
        sc
    } else {
        // For P2WPKH (native or nested), script_code is 1976a914<PKH>88ac
        let pkh = if prevout.scriptpubkey_type == "v0_p2wpkh" {
            hex::decode(&prevout.scriptpubkey[4..])?
        } else {
            // Nested P2WPKH or P2WPKH where we need to derive PKH from public key in witness
            let witness = target_vin.witness.as_ref().context("No witness for P2WPKH")?;
            let pubkey_hex = witness.last().context("No pubkey in witness")?;
            let pubkey_bytes = hex::decode(pubkey_hex)?;
            let mut sha256 = Sha256::new();
            sha256.update(pubkey_bytes);
            let sha256_hash = sha256.finalize();
            let mut ripemd160 = ripemd::Ripemd160::new();
            ripemd160.update(&sha256_hash);
            ripemd160.finalize().to_vec()
        };
        let mut sc = hex::decode("1976a914")?;
        sc.extend(pkh);
        sc.extend(hex::decode("88ac")?) ;
        sc
    };

    let value = prevout.value.to_le_bytes().to_vec();
    let sequence = target_vin.sequence.to_le_bytes().to_vec();

    let mut outputs_raw = Vec::new();
    for vout in &tx.vout {
        outputs_raw.extend(&vout.value.to_le_bytes());
        let spk_bytes = hex::decode(&vout.scriptpubkey)?;
        outputs_raw.extend(get_varint_bytes(spk_bytes.len() as u64));
        outputs_raw.extend(spk_bytes);
    }
    let hash_outputs = double_sha256(&outputs_raw);

    let locktime = tx.locktime.to_le_bytes().to_vec();
    let sighash_type = 1u32.to_le_bytes().to_vec();

    let mut preimage = Vec::new();
    preimage.extend(version);
    preimage.extend(hash_prevouts);
    preimage.extend(hash_sequence);
    preimage.extend(outpoint);
    preimage.extend(script_code);
    preimage.extend(value);
    preimage.extend(sequence);
    preimage.extend(hash_outputs);
    preimage.extend(locktime);
    preimage.extend(sighash_type);

    Ok(hex::encode(double_sha256(&preimage)))
}

fn parse_der(sig_hex: &str) -> Option<(String, String)> {
    if sig_hex.len() < 10 { return None; }
    
    // Find the start of the DER sequence (0x30)
    // Sometimes it's prefixed by length or other script data
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

async fn fetch_tx_data(client: &reqwest::Client, txid: &str) -> Result<MempoolTx> {
    let url = format!("https://mempool.space/api/tx/{}", txid);
    let ua = USER_AGENTS.choose(&mut rand::thread_rng()).unwrap();
    let resp = client.get(url)
        .header("User-Agent", *ua)
        .send().await?
        .json::<MempoolTx>().await?;
    Ok(resp)
}

async fn analyze_address(client: Arc<reqwest::Client>, address: String, sem: Arc<Semaphore>) -> Result<Vec<ExtractedSig>> {
    let _permit = sem.acquire().await?;
    println!("[INFO] Analyzing address: {}", address);

    let mut all_extracted = Vec::new();
    let mut last_txid = None;
    
    loop {
        let url = if let Some(txid) = &last_txid {
            format!("https://mempool.space/api/address/{}/txs/chain/{}", address, txid)
        } else {
            format!("https://mempool.space/api/address/{}/txs/chain", address)
        };
        
        let ua = USER_AGENTS.choose(&mut rand::thread_rng()).unwrap();
        let resp = client.get(url).header("User-Agent", *ua).send().await?;
        if !resp.status().is_success() {
            if resp.status().as_u16() == 429 {
                sleep(Duration::from_secs(10)).await;
                continue;
            }
            break;
        }
        let txs = resp.json::<Vec<MempoolTx>>().await?;
        if txs.is_empty() { break; }
        println!("[DEBUG] Fetched {} transactions for {}", txs.len(), address);
        
        last_txid = txs.last().map(|t| t.txid.clone());

        for tx in txs {
            for (vin_idx, vin) in tx.vin.iter().enumerate() {
                let prevout = match &vin.prevout {
                    Some(p) => p,
                    None => continue,
                };

                if prevout.scriptpubkey_address.as_deref() == Some(&address) {
                    println!("[DEBUG] Found spend transaction: {} for {}", tx.txid, address);
                    
                    // Priority: Witness contains the signature for SegWit (including nested P2SH)
                    let sig_hex = if let Some(w) = &vin.witness {
                        if !w.is_empty() {
                            w.first().cloned().unwrap_or_default()
                        } else {
                            vin.scriptsig.clone().unwrap_or_default()
                        }
                    } else {
                        vin.scriptsig.clone().unwrap_or_default()
                    };

                    if let Some((r, s)) = parse_der(&sig_hex) {
                        let is_segwit = vin.witness.as_ref().map(|w| !w.is_empty()).unwrap_or(false);
                        
                        let z = if is_segwit {
                            get_real_z_segwit(&tx, vin_idx).ok()
                        } else {
                            match prevout.scriptpubkey_type.as_str() {
                                "p2pkh" | "p2sh" => get_real_z_legacy(&tx, vin_idx).ok(),
                                _ => {
                                    println!("[DEBUG] Unsupported legacy script type: {}", prevout.scriptpubkey_type);
                                    None
                                }
                            }
                        };

                        if let Some(z_val) = z {
                            println!("[DEBUG] Successfully extracted sig for {}", address);
                            let pubkey = if let Some(w) = &vin.witness {
                                if w.len() >= 2 {
                                    w.last().cloned().unwrap_or_default()
                                } else {
                                    vin.scriptsig_asm.as_ref().map(|asm| asm.split_whitespace().last().unwrap_or_default().to_string()).unwrap_or_default()
                                }
                            } else {
                                vin.scriptsig_asm.as_ref().map(|asm| asm.split_whitespace().last().unwrap_or_default().to_string()).unwrap_or_default()
                            };

                            all_extracted.push(ExtractedSig {
                                r, s, z: z_val,
                                txid: tx.txid.clone(),
                                vin: vin_idx as u32,
                                pubkey,
                                timestamp: tx.status.block_time,
                            });
                        } else {
                            println!("[DEBUG] Failed to calculate Z for {} (type: {}, segwit: {})", tx.txid, prevout.scriptpubkey_type, is_segwit);
                        }
                    } else {
                        println!("[DEBUG] Failed to parse DER signature for {} in tx {}", address, tx.txid);
                    }
                }
            }
        }
        
        if all_extracted.len() > 500 { break; } // Limit per address
        sleep(Duration::from_millis(500)).await; // Small delay between pages
    }
    
    Ok(all_extracted)
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("[START] Address Analyzer Service started.");
    
    loop {
        let conn = Connection::open(DB_FILE)?;
    let _ = conn.pragma_update(None, "busy_timeout", &5000);
        
        // 1. Identify vulnerable addresses from DB
        let mut stmt = conn.prepare("
            SELECT address FROM addresses 
            WHERE (status = 'Spent/Active' 
            OR potential_weakness != 'None Identified'
            OR label = 'Lattice Target'
            OR status = 'Target'
            OR transactions > 0)
            AND (sigs_fetched = 0 OR sigs_fetched IS NULL)
            ORDER BY transactions DESC, balance DESC
            LIMIT 50
        ")?;
        
        let addresses: Vec<String> = stmt.query_map([], |row| row.get(0))?
            .flatten()
            .collect();

        if addresses.is_empty() {
            println!("[INFO] No new target addresses to analyze. Sleeping...");
            sleep(Duration::from_secs(60)).await;
            continue;
        }

        println!("[START] Found {} target addresses to analyze.", addresses.len());

        let client = Arc::new(reqwest::Client::new());
        let sem = Arc::new(Semaphore::new(3)); // Rate limiting
        
        let mut tasks = Vec::new();
        for addr in addresses {
            let c = Arc::clone(&client);
            let s = Arc::clone(&sem);
            tasks.push(tokio::spawn(async move {
                (addr.clone(), analyze_address(c, addr, s).await)
            }));
        }

        let results = join_all(tasks).await;
        
        let mut total_sigs = 0;
        for res in results {
            if let Ok((addr, Ok(sigs))) = res {
                if sigs.is_empty() { 
                    // Still mark as fetched even if 0 sigs found, to avoid retrying immediately
                    let conn = Connection::open(DB_FILE)?;
    let _ = conn.pragma_update(None, "busy_timeout", &5000);
                    let _ = conn.execute("UPDATE addresses SET sigs_fetched = 1 WHERE address = ?1", params![addr]);
                    continue; 
                }
                println!("[SUCCESS] Extracted {} sigs for {}", sigs.len(), addr);
                total_sigs += sigs.len();
                
                // Save to DB
                let conn = Connection::open(DB_FILE)?;
    let _ = conn.pragma_update(None, "busy_timeout", &5000);
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
                // Mark address as sigs_fetched
                let _ = conn.execute("UPDATE addresses SET sigs_fetched = 1 WHERE address = ?1", params![addr]);
            }
        }

        println!("[FINISH] Collected total of {} signatures. Sleeping...", total_sigs);
        sleep(Duration::from_secs(60)).await;
    }
}
