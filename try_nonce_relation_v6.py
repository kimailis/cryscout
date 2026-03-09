import json
import sys
import multiprocessing
from ecdsa import SECP256k1, VerifyingKey
from ecdsa.ellipticcurve import Point

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = SECP256k1.generator

def check_pair_fast(args):
    i, j, sigs, target_pubkey_hex, limit = args
    s1_data = sigs[i]
    r1, s1, z1 = s1_data['r'], s1_data['s'], s1_data['z']
    s2_data = sigs[j]
    r2, s2, z2 = s2_data['r'], s2_data['s'], s2_data['z']
    
    # target_pubkey point
    pubkey_str = target_pubkey_hex
    if pubkey_str.startswith('0x'): pubkey_str = pubkey_str[2:]
    vk = VerifyingKey.from_string(bytes.fromhex(pubkey_str), curve=SECP256k1)
    Q = vk.pubkey.point

    # P1 = (z2*s1)*G + (r2*s1)*Q
    # P2 = (z1*s2)*G + (r1*s2)*Q
    P1 = ((z2 * s1) % P) * G + ((r2 * s1) % P) * Q
    P2 = ((z1 * s2) % P) * G + ((r1 * s2) % P) * Q
    
    # Check if a*P1 == b*P2 for a, b in 1..limit
    # Use a hash map for O(limit)
    p1_multiples = {}
    curr_p1 = P1
    for a in range(1, limit + 1):
        p1_multiples[(curr_p1.x(), curr_p1.y())] = a
        curr_p1 += P1
        
    curr_p2 = P2
    for b in range(1, limit + 1):
        if (curr_p2.x(), curr_p2.y()) in p1_multiples:
            a = p1_multiples[(curr_p2.x(), curr_p2.y())]
            num = (z2 * s1 * a - z1 * s2 * b) % P
            den = (r1 * s2 * b - r2 * s1 * a) % P
            if den != 0:
                d = (num * pow(den, -1, P)) % P
                return (i, j, a, b, d, "k_i = (a/b) * k_j")
        curr_p2 += P2
        
    # Check for k_i = k_j + c
    # d * (r1*s2 - r2*s1) = z2*s1 - z1*s2 + c*s2*s1
    # P_diff = Q * (r1*s2 - r2*s1) - (z2*s1 - z1*s2) * G
    # P_base = (s2*s1) * G
    # Find c such that P_diff = c * P_base
    p_diff = ((r1 * s2 - r2 * s1) % P) * Q + ((z1 * s2 - z2 * s1) % P) * G
    p_base = ((s2 * s1) % P) * G
    curr_p_base = p_base
    for c in range(1, limit * 10 + 1): # Try larger limit for c
        if (p_diff.x(), p_diff.y()) == (curr_p_base.x(), curr_p_base.y()):
            num = (z2 * s1 - z1 * s2 + c * s2 * s1) % P
            den = (r1 * s2 - r2 * s1) % P
            if den != 0:
                d = (num * pow(den, -1, P)) % P
                return (i, j, 0, c, d, "k_i = k_j + c")
        curr_p_base += p_base

    return None

def try_nonce_relation_v6(filename, target_pubkey_hex, limit=100):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    n = len(sigs)
    print(f"Checking for Nonce Relations in {n} sigs with limit {limit}...")
    
    pairs = []
    for i in range(n):
        for j in range(i + 1, n):
            pairs.append((i, j, sigs, target_pubkey_hex, limit))
    
    print(f"Total pairs to check: {len(pairs)}")
    
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        for result in pool.imap_unordered(check_pair_fast, pairs, chunksize=50):
            if result:
                i, j, a, b, d, relation = result
                print(f"\n!!! SUCCESS !!!")
                print(f"Relation found: {relation}")
                if a != 0:
                    print(f"Indices: {i}, {j} | a: {a}, b: {b}")
                else:
                    print(f"Indices: {i}, {j} | c: {b}")
                print(f"Private Key: {hex(d)}")
                pool.terminate()
                return d
            
    print("\nNo nonce relation found.")
    return None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 try_nonce_relation_v6.py <sigs.json> <pubkey_hex> [limit]")
    else:
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 100
        try_nonce_relation_v6(sys.argv[1], sys.argv[2], limit)
