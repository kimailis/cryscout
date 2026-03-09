import requests
import re

TXID = "c097a280bfed180a99d579053473408b8f0caa1c886bbc819fda65b08d590728"
resp = requests.get(f"https://mempool.space/api/tx/{TXID}")
tx = resp.json()

def parse_der(sig_hex):
    match = re.search(r'30[0-9a-f]{2}02([0-9a-f]{2})([0-9a-f]+)02([0-9a-f]{2})([0-9a-f]+)', sig_hex)
    if match:
        return match.group(2), match.group(4)
    return None, None

for i, vin in enumerate(tx['vin']):
    witness = vin.get('witness', [])
    if witness:
        r, s = parse_der(witness[0])
        print(f"Input {i}: R={r}, S={s}")
