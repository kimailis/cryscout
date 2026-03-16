import json
import sys
import collections
from ecdsa import SECP256k1

P = SECP256k1.order

def check_msb(sigs, bits=8):
    print(f"Checking for {bits}-bit MSB bias...")
    
    # Since we don't know d, we check if (s*k - z)/r is consistent.
    # Actually, let's just check if nonces k have common MSBs.
    # But we can't know k without d.
    
    # Let's try the common 'd mod mod' we found
    d_mod = 863 # from 11-bit LSB
    mod = 2048
    
    msb_counts = collections.Counter()
    for s in sigs:
        try:
            s_inv = pow(s['s'], -1, P)
            u = (s_inv * s['z']) % P
            t = (s_inv * s['r']) % P
            
            # If we know d mod mod, we know k mod mod.
            # a = (u + t*d_mod) % mod
            # But that doesn't help with MSB.
            pass
            
    # Try another way: autocorrelation of nonces
    # P_i = k_i * G = s_i^-1 * (z_i * G + r_i * Q)
    # We can check if P_i have any patterns.
    pass

if __name__ == "__main__":
    with open('sigs_15Z5YJaa_all.json', 'r') as f:
        sigs = json.load(f)
    # check_msb(sigs)
    
    # Just print first few nonces if we assume some d?
    # No, let's look for EXACT matches in nonces again.
    # (Already did, found none).
