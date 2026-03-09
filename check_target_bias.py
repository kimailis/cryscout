import requests
import re

def get_tx_sigs(txid, address):
    url = f"https://mempool.space/api/tx/{txid}"
    resp = requests.get(url)
    if resp.status_code != 200: return []
    tx = resp.json()
    sigs = []
    for vin in tx.get('vin', []):
        if vin.get('prevout', {}).get('scriptpubkey_address') == address:
            witness = vin.get('witness', [])
            scriptsig = vin.get('scriptsig', "")
            raw_sigs = []
            if witness: raw_sigs.extend(witness)
            if scriptsig: raw_sigs.append(scriptsig)
            for sig in raw_sigs:
                try:
                    sig_bytes = bytes.fromhex(sig)
                    if sig_bytes[0] == 0x30:
                        r_len = sig_bytes[3]
                        r_val = sig_bytes[4:4+r_len]
                        r_int = int.from_bytes(r_val, 'big')
                        sigs.append({'txid': txid, 'r': r_int})
                except: pass
    return sigs

if __name__ == "__main__":
    addr = 'bc1ql5hlr8ugqlav2ct3p0c5zwvjyarf0afgh6f5v6'
    txids = [
        '5b2b7b53f7bb55a1f234edc2c864542f182c31b2dc02e4212efcaafcacef2fce',
        'b25dc6df806fd4eecf6d56cb64af02b8581a17bf0c0bad12aba767b5492d87c3',
        '942e8a9e0a3454826563aefc63263cf934659afa9301e2602cc66b12432a6ff1',
        '2740d295888a28655a5667f7793d19b28d79d12efa4df8d01e3b47940a5090c8',
        'a9fffb06787814ebfdc03d29670ccd99bbb25c4c59dc06822a0ac295aee21f28',
        '812c45f65c909914ccd06f807aa98a4b3aefd676f962fdaaaaa6ba1300f8f570',
        'c9b1c9cb06f6eb6025287f4ce8d98ba7aae2511d2eb33bb1c3b36a7a03ce2a08',
        'ddd9dd4392046845e0e3fd285310895aad0bb96480aed4d959528ae22ca3f3d5',
        '529fd728db6c20f0c702956480ab5d67a7c4af800a2f9ae8f2d4a7b7ecbcb34f'
    ]
    for txid in txids:
        sigs = get_tx_sigs(txid, addr)
        for s in sigs:
            print(f"TX: {s['txid']} | R-Bits: {s['r'].bit_length()}")
