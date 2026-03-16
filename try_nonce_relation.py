import json
import sys
import hashlib
import base58
from ecdsa import SigningKey, SECP256k1

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def get_target_hashes(address):
    hashes = []
    if address.startswith('1'):
        try:
            decoded = base58.b58decode(address)
            # Legacy address: 1 byte prefix (0x00) + 20 bytes hash + 4 bytes checksum
            if len(decoded) == 25:
                hashes.append(decoded[1:21])
        except:
            pass
    elif address.startswith('bc1q'):
        # For SegWit, we'd need bech32 decoding, but let's focus on legacy for now
        pass
    return hashes

def fast_verify(d, target_hashes):
    try:
        d_hex = hex(int(d))[2:].zfill(64)
        d_bytes = bytes.fromhex(d_hex)
        sk = SigningKey.from_string(d_bytes, curve=SECP256k1)
        vk = sk.verifying_key
        
        # Check compressed and uncompressed
        for compressed in [True, False]:
            pubkey_bytes = vk.to_string('compressed' if compressed else 'uncompressed')
            sha256 = hashlib.sha256(pubkey_bytes).digest()
            h160 = hashlib.new('ripemd160', sha256).digest()
            if h160 in target_hashes:
                return True
    except:
        pass
    return False

def try_nonce_relation(filename, address):
    with open(filename, "r") as f:
        sigs_raw = json.load(f)
    sigs = []
    for s in sigs_raw:
        sigs.append({
            'r': int(s['r']),
            's': int(s['s']),
            'z': int(s['z'])
        })
    
    target_hashes = get_target_hashes(address)
    print(f"Target address: {address}")
    print(f"Target hashes: {[h.hex() for h in target_hashes]}")
    
    print(f"Checking for Nonce Relations (k_i = c * k_j) in {len(sigs)} sigs...")
    
    for i in range(len(sigs)):
        if i % 10 == 0: print(f"Processing sig {i}/{len(sigs)}...")
        for j in range(i + 1, len(sigs)):
            s1, s2 = sigs[i], sigs[j]
            for c in range(1, 100):
                # Try c and 1/c
                for val_c in [c, pow(c, -1, P)]:
                    # d = (s1*val_c*z2 - s2*z1) * (s2*r1 - s1*val_c*r2)^-1
                    num = (s1['s'] * val_c * s2['z'] - s2['s'] * s1['z']) % P
                    den = (s2['s'] * s1['r'] - s1['s'] * val_c * s2['r']) % P
                    
                    if den != 0:
                        d = (num * pow(den, -1, P)) % P
                        if fast_verify(d, target_hashes):
                            print(f"!!! SUCCESS !!! Nonce relation found: k_{i} = {val_c} * k_{j}")
                            print(f"Private Key: {hex(d)}")
                            return d

    print(f"Checking for Nonce Relations (k_i = k_j + delta) in {len(sigs)} sigs...")
    for i in range(len(sigs)):
        if i % 10 == 0: print(f"Processing sig {i}/{len(sigs)}...")
        for j in range(i + 1, len(sigs)):
            s1, s2 = sigs[i], sigs[j]
            for delta in range(-100, 100):
                if delta == 0: continue
                # d = (s2*z1 - s1*z2 - s1*s2*delta) * (s1*r2 - s2*r1)^-1
                num = (s2['s'] * s1['z'] - s1['s'] * s2['z'] - s1['s'] * s2['s'] * delta) % P
                den = (s1['s'] * s2['r'] - s2['s'] * s1['r']) % P
                if den != 0:
                    d = (num * pow(den, -1, P)) % P
                    if fast_verify(d, target_hashes):
                        print(f"!!! SUCCESS !!! Nonce relation found: k_{i} = k_{j} + {delta}")
                        print(f"Private Key: {hex(d)}")
                        return d
    print("No simple nonce relation found.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 try_nonce_relation.py <sigs.json> <address>")
    else:
        try_nonce_relation(sys.argv[1], sys.argv[2])
