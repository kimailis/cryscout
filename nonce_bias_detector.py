import pandas as pd
import requests
import time
import os
import re

from db_manager import add_finding

def detect_bias(address):
    print(f"Checking for nonce bias (small r-values) in: {address}")
    url = f"https://mempool.space/api/address/{address}/txs"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            txs = response.json()
            found_bias = False
            for tx in txs:
                tx_hash = tx.get('txid')
                for vin in tx.get('vin', []):
                    # Extract from both scriptsig and witness
                    sigs = []
                    if vin.get('scriptsig'): sigs.append(vin['scriptsig'])
                    if vin.get('witness'): sigs.extend(vin['witness'])
                    
                    for sig in sigs:
                        # ECDSA DER Check
                        match = re.search(r'30[0-9a-f]{2}02([0-9a-f]{2})([0-9a-f]+)02', sig)
                        if match:
                            r_len_hex = match.group(1)
                            r_len = int(r_len_hex, 16)
                            r_value_hex = match.group(2)[:r_len*2]
                            r_int = int(r_value_hex, 16)
                            
                            if r_int < (1 << 128):
                                print(f"!!! BIASED ECDSA NONCE CANDIDATE FOUND !!!")
                                add_finding(address, 'ECDSA Bias', txid=tx_hash, details={'r_bits': r_int.bit_length(), 'r_hex': r_value_hex}, severity='High')
                                with open("bias_candidates.txt", "a") as f:
                                    f.write(f"Type: ECDSA\nAddress: {address}\nTX: {tx_hash}\nR-Bits: {r_int.bit_length()}\nHex: {r_value_hex}\n\n")
                                found_bias = True
                        
                        # Schnorr (Taproot) Check (64 bytes hex)
                        elif len(sig) == 128:
                            r_value_hex = sig[:64]
                            r_int = int(r_value_hex, 16)
                            if r_int < (1 << 128):
                                print(f"!!! BIASED SCHNORR NONCE CANDIDATE FOUND !!!")
                                add_finding(address, 'Schnorr Bias', txid=tx_hash, details={'r_bits': r_int.bit_length(), 'r_hex': r_value_hex}, severity='High')
                                with open("bias_candidates.txt", "a") as f:
                                    f.write(f"Type: Schnorr\nAddress: {address}\nTX: {tx_hash}\nR-Bits: {r_int.bit_length()}\nHex: {r_value_hex}\n\n")
                                found_bias = True
            return found_bias
    except Exception as e:
        print(f"Error checking {address}: {e}")
    return False

def run_bias_check():
    if not os.path.exists("analyzed_addresses.csv"):
        print("Run analyze_addresses.py first.")
        return
    df = pd.read_csv("analyzed_addresses.csv")
    active = df[df['Status'] == 'Spent/Active']
    
    for addr in active['Address']:
        detect_bias(addr)
        time.sleep(2)

if __name__ == "__main__":
    run_bias_check()
