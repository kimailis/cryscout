#!/usr/bin/env python3
import requests
import time
import json
from db_manager import get_connection, save_signatures, mark_stage_done

def harvest_signatures_for_p2pk(limit=50):
    """
    Harvest signatures for P2PK addresses.
    Since P2PK addresses are the public keys themselves, we search the blockchain
    to see if these public keys have ever appeared in ANY transaction.
    """
    conn = get_connection()
    c = conn.cursor()
    # Target P2PK addresses that haven't had sigs fetched recently
    c.execute("""
        SELECT DISTINCT a.address, s.pubkey_hex FROM addresses a
        JOIN signatures s ON a.address = s.address
        WHERE a.type LIKE 'P2PK%' AND a.sigs_fetched = 0
        LIMIT ?
    """, (limit,))
    targets = c.fetchall()
    conn.close()
    
    if not targets:
        print("[Harvester] No P2PK targets needing signature harvesting.")
        return

    print(f"[Harvester] Attempting to harvest signatures for {len(targets)} P2PK targets...")
    
    for addr, pubkey in targets:
        if not pubkey:
            # Try to find pubkey from signatures table if it was inserted there
            conn = get_connection()
            c = conn.cursor()
            c.execute("SELECT pubkey_hex FROM signatures WHERE address = ? AND pubkey_hex IS NOT NULL", (addr,))
            row = c.fetchone()
            conn.close()
            if row: pubkey = row[0]
            else: continue

        print(f"  Target: {addr} (PubKey: {pubkey[:20]}...)")
        
        # Use an indexer that allows searching by PubKey if possible.
        # Mempool.space doesn't have a direct "search by pubkey" API, 
        # but we can check the address's own transactions.
        try:
            url = f"https://mempool.space/api/address/{addr}/txs"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                txs = resp.json()
                print(f"    Found {len(txs)} transactions for address.")
                # The actual signature extraction happens in tx_preimage_reconstructor
                # This harvester just triggers the fetch stage.
                from tx_preimage_reconstructor import extract_sigs_with_real_z
                sigs = extract_sigs_with_real_z(addr)
                if sigs:
                    save_signatures(addr, sigs)
                    print(f"    [+] Saved {len(sigs)} signatures for {addr}")
            
            mark_stage_done(addr, 'fetching', 'Harvester-P2PK')
            time.sleep(1)
        except Exception as e:
            print(f"    Error harvesting {addr}: {e}")

if __name__ == "__main__":
    harvest_signatures_for_p2pk()
