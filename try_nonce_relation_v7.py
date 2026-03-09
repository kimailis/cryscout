import json
import sys
from ecdsa import SECP256k1, VerifyingKey

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = SECP256k1.generator

def check_pair(i, j, sigs, Q, limit):
    s1_data = sigs[i]
    r1, s1, z1 = s1_data['r'], s1_data['s'], s1_data['z']
    s2_data = sigs[j]
    r2, s2, z2 = s2_data['r'], s2_data['s'], s2_data['z']
    
    # P1 = (z2*s1)*G + (r2*s1)*Q
    # P2 = (z1*s2)*G + (r1*s2)*Q
    # a*P1 = b*P2 => k1 = (a/b)*k2
    P1 = ((z2 * s1) % P) * G + ((r2 * s1) % P) * Q
    P2 = ((z1 * s2) % P) * G + ((r1 * s2) % P) * Q
    
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
                return d, f"k_{i} = ({a}/{b}) * k_{j}"
        curr_p2 += P2
        
    # Check for k_i = k_j + c
    p_diff = ((r1 * s2 - r2 * s1) % P) * Q + ((z1 * s2 - z2 * s1) % P) * G
    p_base = ((s2 * s1) % P) * G
    curr_p_base = p_base
    for c in range(1, limit * 10 + 1):
        if (p_diff.x(), p_diff.y()) == (curr_p_base.x(), curr_p_base.y()):
            num = (z2 * s1 - z1 * s2 + c * s2 * s1) % P
            den = (r1 * s2 - r2 * s1) % P
            if den != 0:
                d = (num * pow(den, -1, P)) % P
                return d, f"k_{i} = k_{j} + {c}"
        curr_p_base += p_base
    
    return None, None

def try_nonce_relation_v7(filename, target_pubkey_hex):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    n = len(sigs)
    pubkey_str = target_pubkey_hex
    if pubkey_str.startswith('0x'): pubkey_str = pubkey_str[2:]
    vk = VerifyingKey.from_string(bytes.fromhex(pubkey_str), curve=SECP256k1)
    Q = vk.pubkey.point
    
    print(f"Checking for Nonce Relations in {n} sigs (prioritizing nearby pairs)...")
    
    # Check gaps from 1 to 20
    for gap in range(1, 21):
        print(f"Checking gap {gap}...")
        for i in range(n - gap):
            j = i + gap
            d, rel = check_pair(i, j, sigs, Q, 1000) # Large limit for nearby pairs
            if d:
                print(f"\n!!! SUCCESS !!!")
                print(f"Relation: {rel}")
                print(f"Private Key: {hex(d)}")
                return d
                
    print("\nNo nonce relation found in nearby pairs.")
    return None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 try_nonce_relation_v7.py <sigs.json> <pubkey_hex>")
    else:
        try_nonce_relation_v7(sys.argv[1], sys.argv[2])
