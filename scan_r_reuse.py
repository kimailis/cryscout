import pandas as pd
import requests
import time
import hashlib
import sys

def check_r_reuse(address):
    print(f"Checking {address} for R reuse (paging)...")
    last_txid = None
    seen_r = {}
    
    for page in range(5): # Limit to 5 pages per address to keep it fast
        url = f"https://mempool.space/api/address/{address}/txs/chain"
        if last_txid: url += f"/{last_txid}"
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200: break
            txs = resp.json()
            if not txs: break
            
            for tx in txs:
                txid = tx['txid']
                last_txid = txid
                for i, vin in enumerate(tx.get('vin', [])):
                    if vin.get('prevout', {}).get('scriptpubkey_address') == address:
                        scriptsig = vin.get('scriptsig', '')
                        witness = vin.get('witness', [])
                        sigs = []
                        if scriptsig: sigs.append(scriptsig)
                        if witness: sigs.extend(witness)
                        
                        for sig_hex in sigs:
                            try:
                                sig_bytes = bytes.fromhex(sig_hex)
                                # Find DER 0x30
                                idx = sig_bytes.find(b'\x30')
                                if idx == -1: continue
                                r_tag_idx = idx + 2
                                r_len = sig_bytes[r_tag_idx+1]
                                r_val = sig_bytes[r_tag_idx+2 : r_tag_idx+2+r_len]
                                r_int = int.from_bytes(r_val, 'big')
                                
                                s_tag_idx = r_tag_idx + 2 + r_len
                                s_len = sig_bytes[s_tag_idx+1]
                                s_val = sig_bytes[s_tag_idx+2 : s_tag_idx+2+s_len]
                                s_int = int.from_bytes(s_val, 'big')
                                
                                if r_int in seen_r:
                                    old = seen_r[r_int]
                                    if old['txid'] == txid: continue
                                    print(f"!!! R REUSE DETECTED in {address} !!!")
                                    with open("r_reuse_found.txt", "a") as f:
                                        f.write(f"Address: {address} | R: {hex(r_int)} | TX1: {old['txid']} | TX2: {txid}\n")
                                    return True
                                else:
                                    seen_r[r_int] = {'txid': txid, 's': s_int}
                            except: pass
            time.sleep(0.5)
        except: break
    return False

def main():
    df = pd.read_csv("analyzed_addresses.csv")
    active = df[df['Status'] == 'Spent/Active']
    print(f"Scanning {len(active)} active addresses for R reuse...")
    for addr in active['Address']:
        check_r_reuse(addr)
        time.sleep(0.2)

if __name__ == "__main__":
    main()
