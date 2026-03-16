import json
import sys
import collections
from ecdsa import SECP256k1

P = SECP256k1.order

def find_lsb_a(sigs, d_mod, bits):
    mod = 1 << bits
    print(f"Checking d mod {mod} = {d_mod}...")
    
    a_counts = collections.Counter()
    for s in sigs:
        try:
            s_inv = pow(s['s'], -1, P)
            u = (s_inv * s['z']) % P
            t = (s_inv * s['r']) % P
            
            # k = u + t*d (mod P)
            # k mod mod = (u + t*d_mod) mod mod
            a = (u + t * d_mod) % mod
            a_counts[a] += 1
        except: continue
        
    most_common = a_counts.most_common(5)
    print(f"Top a values (k mod {mod}):")
    for a, count in most_common:
        ratio = count / len(sigs)
        print(f"  a = {a:4d} | count = {count:3d} | ratio = {ratio:.4f} (expected {1/mod:.4f})")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 find_lsb_d.py <sigs.json> <d_mod> <bits>")
    else:
        with open(sys.argv[1], "r") as f:
            sigs = json.load(f)
        find_lsb_a(sigs, int(sys.argv[2]), int(sys.argv[3]))
