import requests

TXID = "c097a280bfed180a99d579053473408b8f0caa1c886bbc819fda65b08d590728"
resp = requests.get(f"https://mempool.space/api/tx/{TXID}")
tx = resp.json()

def parse_der_strict(sig_hex):
    data = bytes.fromhex(sig_hex)
    if data[0] != 0x30: return None, None
    r_tag = data[2]
    r_len = data[3]
    r_val = data[4:4+r_len].hex()
    s_tag = data[4+r_len]
    s_len = data[5+r_len]
    s_val = data[6+r_len:6+r_len+s_len].hex()
    return r_val, s_val

for i, vin in enumerate(tx['vin']):
    witness = vin.get('witness', [])
    if witness:
        r, s = parse_der_strict(witness[0])
        print(f"Input {i}: R={r}\n         S={s}")
