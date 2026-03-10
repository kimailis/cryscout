#!/usr/bin/env python3
import requests
import time
import sqlite3
from db_manager import upsert_address, get_connection
from lattice_nonce_analyzer import pubkey_to_address

def fetch_satoshi_era_p2pk(start_block=0, end_block=2000, step=10):
    """
    Fetch Satoshi-era P2PK addresses from early block heights.
    """
    print(f"[Fetcher] Target: Blocks {start_block} to {end_block} (step={step})...")
    found = 0
    
    for height in range(start_block, end_block + 1, step):
        try:
            # 1. Get block hash from height
            h_resp = requests.get(f"https://mempool.space/api/block-height/{height}", timeout=10)
            if h_resp.status_code != 200:
                continue
            block_hash = h_resp.text.strip()
            
            # 2. Get block transactions
            tx_resp = requests.get(f"https://mempool.space/api/block/{block_hash}/txs", timeout=10)
            if tx_resp.status_code != 200:
                continue
            txs = tx_resp.json()
            
            # 3. Analyze coinbase transaction (index 0)
            if not txs: continue
            cb = txs[0]
            
            for vout in cb.get('vout', []):
                spk = vout.get('scriptpubkey', '')
                spk_type = vout.get('scriptpubkey_type', '')
                
                # Check for P2PK (starts with 41, ends with ac, or length 134/130)
                if spk_type == 'p2pk' or (spk.startswith('41') and spk.endswith('ac')):
                    pubkey = spk[2:-2] # Strip 0x41 prefix and 0xac suffix
                    addr = pubkey_to_address(bytes.fromhex(pubkey))
                    
                    value = vout.get('value', 0) / 1e8
                    
                    upsert_address({
                        'address': addr,
                        'balance': value,
                        'current_balance': value,
                        'status': 'Target',
                        'type': f'P2PK (Block {height})',
                        'accessibility': 'Exposed PubKey'
                    })
                    
                    # Store the pubkey in the signatures table as a base reference
                    conn = get_connection()
                    c = conn.cursor()
                    c.execute("INSERT OR IGNORE INTO signatures (address, pubkey_hex, is_biased) VALUES (?, ?, 0)", (addr, pubkey))
                    conn.commit()
                    conn.close()
                    
                    found += 1
                    print(f"    [+] Block {height}: Found P2PK {addr} ({value} BTC)")
            
            time.sleep(0.5) # Be respectful
        except Exception as e:
            print(f"    Error block {height}: {e}")
            continue
            
    print(f"  [+] Finished. Found {found} Satoshi-era P2PK targets.")

if __name__ == "__main__":
    # We can run in batches to avoid overwhelming APIs
    # Expanded range to block 50,000 (Early 2010)
    fetch_satoshi_era_p2pk(start_block=2001, end_block=50000, step=200)
