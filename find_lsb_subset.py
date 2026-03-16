import json
import sys
from ecdsa import SECP256k1

P = SECP256k1.order

def find_subset(sigs, d_mod, a, bits):
    mod = 1 << bits
    subset = []
    for s in sigs:
        try:
            s_inv = pow(s['s'], -1, P)
            u = (s_inv * s['z']) % P
            t = (s_inv * s['r']) % P
            
            # Check if (u + t*d_mod) % mod == a
            if (u + t * d_mod) % mod == a:
                subset.append(s)
        except: continue
        
    print(f"Found {len(subset)} signatures matching d mod {mod} = {d_mod} and a = {a}")
    return subset

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python3 find_lsb_subset.py <sigs.json> <d_mod> <a> <bits>")
    else:
        with open(sys.argv[1], "r") as f:
            sigs = json.load(f)
        subset = find_subset(sigs, int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]))
        with open("sigs_subset.json", "w") as f:
            json.dump(subset, f)
        print("Saved to sigs_subset.json")
