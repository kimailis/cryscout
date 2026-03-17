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
    let pkh = &prevout.scriptpubkey[4..];
    let mut script_code = hex::decode("1976a914")?;
    script_code.extend(hex::decode(pkh)?);
    script_code.extend(hex::decode("88ac")?);

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
    let start = sig_hex.find("30")?;
    let data = hex::decode(&sig_hex[start..]).ok()?;
    if data.len() < 8 || data[0] != 0x30 { return None; }
    
    let r_len = data[3] as usize;
    if data.len() < 4 + r_len + 2 { return None; }
    let r_bytes = &data[4..4+r_len];
    
    let s_tag_idx = 4 + r_len;
    if data[s_tag_idx] != 0x02 { return None; }
    let s_len = data[s_tag_idx + 1] as usize;
    if data.len() < s_tag_idx + 2 + s_len { return None; }
    let s_bytes = &data[s_tag_idx+2..s_tag_idx+2+s_len];

    Some((hex::encode(r_bytes), hex::encode(s_bytes)))
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

    let url = format!("https://mempool.space/api/address/{}/txs/chain", address);
    let ua = USER_AGENTS.choose(&mut rand::thread_rng()).unwrap();
    let resp = client.get(url).header("User-Agent", *ua).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("Failed to fetch txids for {}", address));
    }
    let txs = resp.json::<Vec<MempoolTx>>().await?;
    
    let mut extracted = Vec::new();
    for tx in txs {
        for (vin_idx, vin) in tx.vin.iter().enumerate() {
            let prevout = match &vin.prevout {
                Some(p) => p,
                None => continue,
            };

            if prevout.scriptpubkey_address.as_deref() == Some(&address) {
                let sig_hex = if let Some(s) = &vin.scriptsig {
                    s.clone()
                } else if let Some(w) = &vin.witness {
                    w.first().cloned().unwrap_or_default()
                } else {
                    continue;
                };

                if let Some((r, s)) = parse_der(&sig_hex) {
                    let z = match prevout.scriptpubkey_type.as_str() {
                        "p2pkh" => get_real_z_legacy(&tx, vin_idx),
                        "v0_p2wpkh" => get_real_z_segwit(&tx, vin_idx),
                        _ => continue,
                    }.ok();

                    if let Some(z_val) = z {
                        let pubkey = if let Some(asm) = &vin.scriptsig_asm {
                            asm.split_whitespace().last().unwrap_or_default().to_string()
                        } else if let Some(w) = &vin.witness {
                            w.last().cloned().unwrap_or_default()
                        } else {
                            String::new()
                        };

                        extracted.push(ExtractedSig {
                            r, s, z: z_val,
                            txid: tx.txid.clone(),
                            vin: vin_idx as u32,
                            pubkey,
                            timestamp: tx.status.block_time,
                        });
                    }
                }
            }
        }
    }
    
    Ok(extracted)
}

#[tokio::main]
async fn main() -> Result<()> {
    let conn = Connection::open(DB_FILE)?;
    
    // 1. Identify vulnerable addresses from DB
    let mut stmt = conn.prepare("
        SELECT address FROM addresses 
        WHERE status = 'Spent/Active' 
        OR potential_weakness != 'None Identified'
        OR label = 'Lattice Target'
        LIMIT 100
    ")?;
    
    let addresses: Vec<String> = stmt.query_map([], |row| row.get(0))?
        .flatten()
        .collect();

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
            if sigs.is_empty() { continue; }
            println!("[SUCCESS] Extracted {} sigs for {}", sigs.len(), addr);
            total_sigs += sigs.len();
            
            // Save to DB
            let conn = Connection::open(DB_FILE)?;
            for sig in sigs {
                let _ = conn.execute(
                    "INSERT OR IGNORE INTO signatures (address, r, s, z, txid, vin, pubkey_hex, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![addr, sig.r, sig.s, sig.z, sig.txid, sig.vin, sig.pubkey, sig.timestamp],
                );
            }
        }
    }

    println!("[FINISH] Collected total of {} signatures.", total_sigs);
    Ok(())
}
