import pandas as pd
import requests
import time
import os
import re
from collections import defaultdict

def check_global_rng_failure():
    if not os.path.exists("analyzed_addresses.csv"):
        print("Run analyze_addresses.py first.")
        return
    
    df = pd.read_csv("analyzed_addresses.csv")
    active = df[df['Status'] == 'Spent/Active']
    
    # Map R-Value -> List of (Address, TX_Hash)
    global_nonces = defaultdict(list)
    
    print(f"Performing Global RNG Failure Analysis on {len(active)} active addresses...")
    
    for addr in active['Address']:
        print(f"Fetching history for: {addr}")
        url = f"https://mempool.space/api/address/{addr}/txs"
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                txs = response.json()
                for tx in txs:
                    tx_hash = tx.get('txid')
                    for vin in tx.get('vin', []):
                        # ONLY check if this address is the one that signed this input
                        prevout = vin.get('prevout', {})
                        if prevout.get('scriptpubkey_address') != addr:
                            continue
                            
                        sigs = []
                        if vin.get('scriptsig'): sigs.append(vin['scriptsig'])
                        if vin.get('witness'): sigs.extend(vin['witness'])
                        
                        for sig in sigs:
                            match = re.search(r'30[0-9a-f]{2}02([0-9a-f]{2})([0-9a-f]+)02', sig)
                            if match:
                                r_len = int(match.group(1), 16)
                                r_val = match.group(2)[:r_len*2]
                                global_nonces[r_val].append((addr, tx_hash))
            time.sleep(1)
        except Exception as e:
            print(f"Error: {e}")

    print("\n--- Global R-Value Collision Report ---")
    collisions_found = False
    for r_val, occurrences in global_nonces.items():
        # Filter for same R-value used by DIFFERENT addresses
        unique_addresses = set([occ[0] for occ in occurrences])
        if len(unique_addresses) > 1:
            collisions_found = True
            print(f"!!! GLOBAL RNG FAILURE DETECTED !!!")
            print(f"R-Value: {r_val}")
            for addr, tx in occurrences:
                print(f"  - Address: {addr} | TX: {tx}")
            
            with open("global_vulnerabilities.txt", "a") as f:
                f.write(f"Global R-Collision!\nR: {r_val}\n")
                for addr, tx in occurrences:
                    f.write(f"  Addr: {addr} TX: {tx}\n")
                f.write("\n")

    if not collisions_found:
        print("No global R-value collisions found across the dataset.")

if __name__ == "__main__":
    check_global_rng_failure()
