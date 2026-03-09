import pandas as pd
import requests
import time
import os
import re
from collections import defaultdict

def verify_rng_failure():
    if not os.path.exists("analyzed_addresses.csv"):
        print("Run analyze_addresses.py first.")
        return
    
    df = pd.read_csv("analyzed_addresses.csv")
    active = df[df['Status'] == 'Spent/Active']
    
    # Map R-Value -> List of (Address, TX_Hash, S_Value)
    r_map = defaultdict(list)
    
    print(f"Verifying RNG for {len(active)} active addresses...")
    
    for i, addr in enumerate(active['Address']):
        print(f"[{i+1}/{len(active)}] Fetching history for: {addr}")
        # Fetch up to 50 transactions
        url = f"https://mempool.space/api/address/{addr}/txs"
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                txs = response.json()
                for tx in txs:
                    tx_hash = tx.get('txid')
                    for vin in tx.get('vin', []):
                        # Verify this input IS from our address
                        prevout = vin.get('prevout', {})
                        if prevout.get('scriptpubkey_address') != addr:
                            continue
                        
                        # Extract signatures from scriptsig or witness
                        sigs = []
                        if vin.get('scriptsig'): sigs.append(vin['scriptsig'])
                        if vin.get('witness'): sigs.extend(vin['witness'])
                        
                        for sig in sigs:
                            # Match DER signature: 30 <len> 02 <r_len> <r> 02 <s_len> <s> <sighash>
                            # We look for the pattern in hex
                            match = re.search(r'30[0-9a-f]{2}02([0-9a-f]{2})([0-9a-f]+)02([0-9a-f]{2})([0-9a-f]+)', sig)
                            if match:
                                r_len = int(match.group(1), 16)
                                r_val = match.group(2)[:r_len*2]
                                s_len = int(match.group(3), 16)
                                s_val = match.group(4)[:s_len*2]
                                r_map[r_val].append({'addr': addr, 'tx': tx_hash, 's': s_val})
            time.sleep(0.5)
        except Exception as e:
            print(f"Error: {e}")

    print("\n--- R-Value Collision Report ---")
    for r_val, signatures in r_map.items():
        if len(signatures) > 1:
            # Check if it's actually different signatures (different S or different TX)
            unique_sigs = set([(s['tx'], s['s']) for s in signatures])
            if len(unique_sigs) > 1:
                print(f"Collision found for R={r_val}")
                for s in signatures:
                    print(f"  Addr: {s['addr']} | TX: {s['tx']} | S: {s['s'][:16]}...")

if __name__ == "__main__":
    verify_rng_failure()
