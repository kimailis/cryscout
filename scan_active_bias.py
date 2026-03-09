import pandas as pd
import requests
import time
import os
import re

def detect_bias(address):
    print(f"Checking {address}...")
    url = f"https://mempool.space/api/address/{address}/txs"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            txs = response.json()
            for tx in txs:
                tx_hash = tx.get('txid')
                for vin in tx.get('vin', []):
                    sigs = []
                    if vin.get('scriptsig'): sigs.append(vin['scriptsig'])
                    if vin.get('witness'): sigs.extend(vin['witness'])
                    
                    for sig in sigs:
                        try:
                            sig_bytes = bytes.fromhex(sig)
                            if sig_bytes[0] == 0x30:
                                r_len = sig_bytes[3]
                                r_val = sig_bytes[4:4+r_len]
                                r_int = int.from_bytes(r_val, 'big')
                                
                                if r_int < (1 << 240): # 16 bits of bias (zeros at start)
                                    print(f"!!! BIAS FOUND in {address} (TX: {tx_hash}) !!!")
                                    print(f"R-Bits: {r_int.bit_length()}")
                                    with open("bias_found.txt", "a") as f:
                                        f.write(f"Address: {address} | TX: {tx_hash} | R-Bits: {r_int.bit_length()}\n")
                        except: pass
    except: pass

def main():
    df = pd.read_csv("analyzed_addresses.csv")
    # Spent/Active addresses are the ones we can analyze sigs for
    active = df[df['Status'] == 'Spent/Active']
    print(f"Scanning {len(active)} active addresses...")
    for addr in active['Address']:
        detect_bias(addr)
        time.sleep(1)

if __name__ == "__main__":
    main()
