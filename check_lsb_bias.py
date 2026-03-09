import requests
import hashlib

def get_tx_sigs(txid, address):
    url = f"https://mempool.space/api/tx/{txid}"
    resp = requests.get(url)
    if resp.status_code != 200: return []
    tx = resp.json()
    sigs = []
    for vin in tx.get('vin', []):
        if vin.get('prevout', {}).get('scriptpubkey_address') == address:
            scriptsig = vin.get('scriptsig', '')
            witness = vin.get('witness', [])
            raw_sigs = []
            if scriptsig: raw_sigs.append(scriptsig)
            if witness: raw_sigs.extend(witness)
            for sig in raw_sigs:
                try:
                    sig_bytes = bytes.fromhex(sig)
                    idx = sig_bytes.find(b'\x30')
                    if idx != -1:
                        r_tag_idx = idx + 2
                        if sig_bytes[r_tag_idx] == 0x02:
                            r_len = sig_bytes[r_tag_idx+1]
                            r_val = sig_bytes[r_tag_idx+2:r_tag_idx+2+r_len]
                            r_int = int.from_bytes(r_val, 'big')
                            sigs.append(r_int)
                except: pass
    return sigs

def check_lsb_bias(address):
    print(f"Checking LSB bias for: {address}")
    last_txid = None
    all_spending_txids = []
    while True:
        url = f"https://mempool.space/api/address/{address}/txs/chain"
        if last_txid: url += f"/{last_txid}"
        resp = requests.get(url)
        if resp.status_code != 200: break
        txs = resp.json()
        if not txs: break
        for tx in txs:
            for vin in tx.get('vin', []):
                if vin.get('prevout', {}).get('scriptpubkey_address') == address:
                    all_spending_txids.append(tx['txid'])
                    break
            last_txid = tx['txid']
        if len(txs) < 25: break # End of history
    
    if not all_spending_txids:
        print("No spending transactions found.")
        return
        
    print(f"Found {len(all_spending_txids)} spending transactions.")
    
    r_values = []
    for txid in all_spending_txids:
        r_values.extend(get_tx_sigs(txid, address))
    
    if not r_values:
        print("No signatures found.")
        return
        
    print(f"Found {len(r_values)} R-values.")
    for i in range(1, 16):
        mod = 1 << i
        counts = {}
        for r in r_values:
            val = r % mod
            counts[val] = counts.get(val, 0) + 1
        
        # Check if any value is suspiciously frequent
        for val, count in counts.items():
            if count > len(r_values) * 0.7 and len(r_values) >= 2:
                print(f"!!! Potential LSB bias detected at bit {i}: mod {mod} = {val} ({count}/{len(r_values)}) !!!")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        check_lsb_bias(sys.argv[1])
    else:
        check_lsb_bias("12ib7dApVFvg82TXKycWBNpN8kFyiAN1dr")
