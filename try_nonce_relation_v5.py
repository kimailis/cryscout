import json
import sys
import multiprocessing
from ecdsa import SECP256k1, VerifyingKey

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = SECP256k1.generator

def check_pair(args):
    i, j, sigs, target_pubkey_hex, limit = args
    s1_data = sigs[i]
    r1, s1, z1 = s1_data['r'], s1_data['s'], s1_data['z']
    s2_data = sigs[j]
    r2, s2, z2 = s2_data['r'], s2_data['s'], s2_data['z']
    
    # Precompute products
    s1_z2 = (s1 * z2) % P
    s2_z1 = (s2 * z1) % P
    s2_r1 = (s2 * r1) % P
    s1_r2 = (s1 * r2) % P

    for a in range(1, limit + 1):
        a_s1_z2 = (a * s1_z2) % P
        a_s1_r2 = (a * s1_r2) % P
        for b in range(1, limit + 1):
            if a == 1 and b == 1: continue
            
            num = (a_s1_z2 - b * s2_z1) % P
            den = (b * s2_r1 - a_s1_r2) % P
            
            if den != 0:
                d = (num * pow(den, -1, P)) % P
                # Fast verification using public key point multiplication
                vk = VerifyingKey.from_public_point(d * G, curve=SECP256k1)
                if vk.to_string('uncompressed').hex() == target_pubkey_hex:
                    return (i, j, a, b, d)
                if vk.to_string('compressed').hex() == target_pubkey_hex:
                    return (i, j, a, b, d)
    return None

def try_nonce_relation_v5(filename, target_pubkey_hex, limit=50):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    n = len(sigs)
    print(f"Checking for Nonce Relations (k_i = (a/b) * k_j) in {n} sigs with limit {limit}...")
    
    pairs = []
    for i in range(n):
        for j in range(i + 1, n):
            pairs.append((i, j, sigs, target_pubkey_hex, limit))
    
    print(f"Total pairs to check: {len(pairs)}")
    
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        for result in pool.imap_unordered(check_pair, pairs, chunksize=100):
            if result:
                i, j, a, b, d = result
                print(f"\n!!! SUCCESS !!!")
                print(f"Nonce relation found: k_{i} = ({a}/{b}) * k_{j}")
                print(f"Private Key: {hex(d)}")
                pool.terminate()
                return d
            
    print("\nNo nonce relation found.")
    return None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 try_nonce_relation_v5.py <sigs.json> <pubkey_hex> [limit]")
    else:
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 50
        try_nonce_relation_v5(sys.argv[1], sys.argv[2], limit)
