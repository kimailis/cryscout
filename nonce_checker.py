import pandas as pd
import requests
import time
import os
import re

def fetch_transactions_mempool(address):
    print(f"Using Mempool.space for: {address}")
    txs = []
    last_txid = None
    while True:
        url = f"https://mempool.space/api/address/{address}/txs"
        if last_txid:
            url += f"/chain/{last_txid}"
        
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            batch = response.json()
            if not batch:
                break
            txs.extend(batch)
            last_txid = batch[-1]['txid']
            if len(batch) < 25: # Mempool returns 25 per page
                break
            time.sleep(1) # Small delay between pages
        elif response.status_code == 429:
            print("Mempool.space rate limit reached.")
            break
        else:
            print(f"Mempool.space error: {response.status_code}")
            break
    return txs

def check_nonce_reuse():
    if not os.path.exists("analyzed_addresses.csv"):
        print("Missing analyzed_addresses.csv. Run analyze_addresses.py first.")
        return

    df = pd.read_csv("analyzed_addresses.csv")
    
    # Filter for addresses with status 'Spent/Active' and multiple transactions
    active_addresses = df[(df['Status'] == 'Spent/Active') & (df['Transactions'] > 1)]
    
    checked_addresses_file = "checked_nonces.csv"
    if os.path.exists(checked_addresses_file):
        checked_df = pd.read_csv(checked_addresses_file)
        already_checked = set(checked_df['Address'].tolist())
    else:
        already_checked = set()

    print(f"Checking {len(active_addresses)} active addresses for nonce (k) reuse (skipping {len(already_checked)} checked)...")
    
    for _, row in active_addresses.iterrows():
        address = row['Address']
        if address in already_checked:
            continue

        print(f"Analyzing history of: {address}")
        
        try:
            # Try Blockchain.info first
            response = requests.get(f"https://blockchain.info/rawaddr/{address}", timeout=10)
            txs = []
            if response.status_code == 200:
                data = response.json()
                txs = data.get('tx', [])
                # Normalize Blockchain.info format to match what we need
                # Blockchain.info already has inputs with scripts
            elif response.status_code == 429:
                print("Blockchain.info rate limit reached. Trying Mempool.space...")
                txs = fetch_transactions_mempool(address)
            
            if txs:
                nonces = {} # r-value -> list of tx hashes
                
                for tx in txs:
                    tx_hash = tx.get('hash') or tx.get('txid')
                    inputs = tx.get('inputs') or tx.get('vin', [])
                    
                    for input_tx in inputs:
                        # 1. Look in scriptsig (Legacy/P2SH)
                        scriptsig = input_tx.get('script') or input_tx.get('scriptsig', '')
                        # 2. Look in witness (Native SegWit/Nested SegWit)
                        witness = input_tx.get('witness', [])
                        
                        potential_sigs = []
                        if scriptsig:
                            potential_sigs.append(scriptsig)
                        if witness:
                            potential_sigs.extend(witness)

                        for sig_candidate in potential_sigs:
                            # DER encoded signatures (standard for BTC v0)
                            # Format: 30 <length> 02 <r_length> <r> 02 <s_length> <s> 01 (sighash)
                            match = re.search(r'30[0-9a-f]{2}02([0-9a-f]{2})([0-9a-f]+)02', sig_candidate)
                            if match:
                                r_len_hex = match.group(1)
                                r_len = int(r_len_hex, 16) * 2 # length in hex characters
                                r_value = match.group(2)[:r_len]
                                
                                if r_value in nonces and nonces[r_value] != tx_hash:
                                    print(f"!!! COLLISION DETECTED !!!")
                                    print(f"Address: {address}")
                                    print(f"R-Value: {r_value}")
                                    print(f"Transaction 1: {nonces[r_value]}")
                                    print(f"Transaction 2: {tx_hash}")
                                    with open("vulnerabilities_found.txt", "a") as vf:
                                        vf.write(f"Nonce Reuse Found!\nAddress: {address}\nR-Value: {r_value}\nTX1: {nonces[r_value]}\nTX2: {tx_hash}\n\n")
                                else:
                                    nonces[r_value] = tx_hash
                            
                            # BIP340 Schnorr signatures (64 bytes hex = 128 chars) - Taproot
                            # Taproot nonces are usually deterministic (BIP340), but we check for reuse.
                            if len(sig_candidate) == 128:
                                # First 32 bytes (64 chars) is R
                                r_value = sig_candidate[:64]
                                if r_value in nonces and nonces[r_value] != tx_hash:
                                    print(f"!!! SCHNORR COLLISION DETECTED !!!")
                                    print(f"Address: {address}")
                                    print(f"R-Value: {r_value}")
                                    with open("vulnerabilities_found.txt", "a") as vf:
                                        vf.write(f"Schnorr Nonce Reuse Found!\nAddress: {address}\nR-Value: {r_value}\nTX1: {nonces[r_value]}\nTX2: {tx_hash}\n\n")
                                else:
                                    nonces[r_value] = tx_hash
                
                print(f"Processed transactions for {address}, check complete.")
                # Mark as checked
                with open(checked_addresses_file, "a") as f:
                    if not os.path.exists(checked_addresses_file) or os.path.getsize(checked_addresses_file) == 0:
                        f.write("Address\n")
                    f.write(f"{address}\n")
            else:
                print(f"Could not fetch transactions for {address}")
        
        except Exception as e:
            print(f"Exception checking {address}: {e}")
            
        time.sleep(5) # Respect APIs

if __name__ == "__main__":
    check_nonce_reuse()
