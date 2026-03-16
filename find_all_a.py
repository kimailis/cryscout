import json
import sys
import collections
from ecdsa import SECP256k1

P = SECP256k1.order

def find_all_a(sigs, d_mod, bits):
    mod = 1 << bits
    a_groups = collections.defaultdict(list)
    for i, s in enumerate(sigs):
        try:
            s_inv = pow(s['s'], -1, P)
            u = (s_inv * s['z']) % P
            t = (s_inv * s['r']) % P
            a = (u + t * d_mod) % mod
            a_groups[a].append(i)
        except: continue
        
    # Print groups with more than 1 signature
    sorted_groups = sorted(a_groups.items(), key=lambda x: len(x[1]), reverse=True)
    for a, indices in sorted_groups:
        if len(indices) > 1:
            print(f"a = {a:5d} | count = {len(indices):2d} | indices = {indices}")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 find_all_a.py <sigs.json> <d_mod> <bits>")
    else:
        with open(sys.argv[1], "r") as f:
            sigs = json.load(f)
        find_all_a(sigs, int(sys.argv[2]), int(sys.argv[3]))
