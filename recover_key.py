import requests
import hashlib
import re
import struct
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_der
from db_manager import add_finding

# The common R-collision TX identified
TXID = "c097a280bfed180a99d579053473408b8f0caa1c886bbc819fda65b08d590728"

def fetch_tx_hex(txid):
    url = f"https://mempool.space/api/tx/{txid}/hex"
    resp = requests.get(url)
    if resp.status_code == 200:
        return resp.text.strip()
    return None

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def get_z_p2pkh(tx_hex, input_index, script_pub_key_hex):
    """
    Computes the message hash (z) for a P2PKH transaction input.
    """
    return None

def recover_from_collision(r, s1, s2, z1, z2):
    n = SECP256k1.order
    def inv(a, n):
        return pow(a, n - 2, n)

    # k = (z1 - z2) / (s1 - s2) mod n
    k = ((z1 - z2) * inv(s1 - s2, n)) % n
    # priv = (s1 * k - z1) / r mod n
    priv = ((s1 * k - z1) * inv(r, n)) % n
    return priv, k

if __name__ == "__main__":
    print(f"Analyzing collision in TX: {TXID}")
    
    resp = requests.get(f"https://mempool.space/api/tx/{TXID}")
    if resp.status_code != 200:
        print("Error fetching TX data")
        exit(1)
    tx_data = resp.json()
    
    vins = tx_data.get('vin', [])
    sigs = []
    print(f"Found {len(vins)} inputs. Parsing signatures...")
    for i, vin in enumerate(vins):
        scriptsig = vin.get('scriptsig', '')
        witness = vin.get('witness', [])
        
        candidates = [scriptsig] + witness
        for candidate in candidates:
            if not candidate: continue
            match = re.search(r'30[0-9a-f]{2}02([0-9a-f]{2})([0-9a-f]+)02([0-9a-f]{2})([0-9a-f]+)', candidate)
            if match:
                r_val = match.group(2)
                s_val = match.group(4)
                r_int = int(r_val, 16)
                s_int = int(s_val, 16)
                addr = vin.get('prevout', {}).get('scriptpubkey_address', 'Unknown')
                print(f"Input {i} ({addr}): R={hex(r_int)[:16]}... S={hex(s_int)[:16]}...")
                sigs.append({'r': r_int, 's': s_int, 'addr': addr})

    seen_r = {}
    for sig in sigs:
        if sig['r'] in seen_r:
            prev = seen_r[sig['r']]
            if sig['s'] != prev['s']:
                print(f"!!! COLLISION FOUND IN THIS TX !!!")
                print(f"R: {hex(sig['r'])}")
                print(f"S1: {hex(prev['s'])}")
                print(f"S2: {hex(sig['s'])}")
                add_finding(sig['addr'], 'R-Collision', txid=TXID, details={'r': hex(sig['r']), 's1': hex(prev['s']), 's2': hex(sig['s'])}, severity='High')
        seen_r[sig['r']] = sig
