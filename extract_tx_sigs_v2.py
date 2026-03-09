import requests
import json
import re
import sys

def get_tx_details(txid, target_address=None):
    url = f"https://mempool.space/api/tx/{txid}"
    resp = requests.get(url)
    if resp.status_code != 200:
        return
    
    tx = resp.json()
    
    for i, vin in enumerate(tx.get('vin', [])):
        prevout = vin.get('prevout', {})
        addr = prevout.get('scriptpubkey_address')
        
        if target_address and addr != target_address:
            continue

        print(f"Transaction: {txid} | Input {i}: {addr}")
        
        witness = vin.get('witness', [])
        scriptsig = vin.get('scriptsig', "")
        
        sigs = []
        if witness: sigs.extend(witness)
        if scriptsig: sigs.append(scriptsig)
        
        for sig in sigs:
            try:
                sig_bytes = bytes.fromhex(sig)
                # Find the 0x30 tag for DER sequence
                idx = sig_bytes.find(b'\x30')
                if idx != -1:
                    r_tag_idx = idx + 2
                    if sig_bytes[r_tag_idx] == 0x02:
                        r_len = sig_bytes[r_tag_idx+1]
                        r_val = sig_bytes[r_tag_idx+2 : r_tag_idx+2+r_len]
                        s_tag_idx = r_tag_idx + 2 + r_len
                        if sig_bytes[s_tag_idx] == 0x02:
                            s_len = sig_bytes[s_tag_idx+1]
                            s_val = sig_bytes[s_tag_idx+2 : s_tag_idx+2+s_len]

                            r_int = int.from_bytes(r_val, 'big')
                            s_int = int.from_bytes(s_val, 'big')

                            print(f"  Parsed Sig: R={r_int.to_bytes(32, 'big').hex()}, S={s_int.to_bytes(32, 'big').hex()}")
                            print(f"  Bit Lengths: R={r_int.bit_length()}, S={s_int.bit_length()}")
            except: pass

def get_address_sigs(address):
    print(f"Fetching transactions for: {address}")
    last_txid = None
    all_spending = []
    for page in range(10):
        url = f"https://mempool.space/api/address/{address}/txs/chain"
        if last_txid: url += f"/{last_txid}"
        resp = requests.get(url)
        if resp.status_code != 200: break
        txs = resp.json()
        if not txs: break
        for tx in txs:
            for vin in tx.get('vin', []):
                if vin.get('prevout', {}).get('scriptpubkey_address') == address:
                    all_spending.append(tx['txid'])
                    break
            last_txid = tx['txid']
        time.sleep(0.5)
    
    print(f"Found {len(all_spending)} spending transactions.")
    for txid in all_spending:
        get_tx_details(txid, address)

import time

if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if len(arg) == 64: # TXID
            get_tx_details(arg)
        else: # Address
            get_address_sigs(arg)
    else:
        txid = "c097a280bfed180a99d579053473408b8f0caa1c886bbc819fda65b08d590728"
        get_tx_details(txid)
