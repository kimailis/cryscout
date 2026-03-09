import requests
import json
import re

def get_tx_details(txid):
    url = f"https://mempool.space/api/tx/{txid}"
    resp = requests.get(url)
    if resp.status_code != 200:
        print(f"Error fetching TX: {resp.status_code}")
        return
    
    tx = resp.json()
    print(f"Transaction: {txid}")
    
    for i, vin in enumerate(tx.get('vin', [])):
        addr = vin.get('prevout', {}).get('scriptpubkey_address')
        print(f"\nInput {i}: {addr}")
        
        scriptsig = vin.get('scriptsig')
        witness = vin.get('witness')
        
        if scriptsig:
            print(f"  ScriptSig: {scriptsig}")
        if witness:
            print(f"  Witness: {witness}")
            
        # Parse DER signature if possible
        # DER format: 30 <len> 02 <r_len> <r> 02 <s_len> <s> <sighash>
        sigs = []
        if scriptsig: sigs.append(scriptsig)
        if witness: sigs.extend(witness)
        
        for sig in sigs:
            # Look for DER pattern in hex string
            match = re.search(r'30[0-9a-f]{2}02([0-9a-f]{2})([0-9a-f]+)02([0-9a-f]{2})([0-9a-f]+)([0-9a-f]{2})', sig)
            if match:
                r_len = int(match.group(1), 16)
                r_val = match.group(2)[:r_len*2]
                s_len = int(match.group(3), 16)
                s_val = match.group(4)[:s_len*2]
                sighash = match.group(5)
                print(f"  Found Sig: R={r_val}, S={s_val}, SigHash={sighash}")

if __name__ == "__main__":
    get_tx_details("c097a280bfed180a99d579053473408b8f0caa1c886bbc819fda65b08d590728")
