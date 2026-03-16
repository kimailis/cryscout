import json
import sys
import collections
from ecdsa import SECP256k1

P = SECP256k1.order

def check_lsb_system(sigs, max_bits=16):
    print(f"Analyzing {len(sigs)} signatures for LSB system bias...")
    
    results = []
    
    # Precompute u and t for all sigs
    prepared = []
    for s in sigs:
        try:
            s_inv = pow(s['s'], -1, P)
            u = (s_inv * s['z']) % P
            t = (s_inv * s['r']) % P
            prepared.append({'u': u, 't': t})
        except: continue
        
    if len(prepared) < 2:
        print("Not enough valid signatures.")
        return

    for b in range(1, max_bits + 1):
        mod = 1 << b
        d_mod_counts = collections.Counter()
        
        # Compare pairs
        # To avoid O(N^2) if N is large, we can limit it
        N = len(prepared)
        max_pairs = 1000000
        pair_count = 0
        
        for i in range(N):
            for j in range(i + 1, N):
                dt = (prepared[i]['t'] - prepared[j]['t']) % mod
                du = (prepared[j]['u'] - prepared[i]['u']) % mod
                
                # Solve dt * d = du (mod mod)
                # This only works if dt is invertible mod mod (i.e., dt is odd)
                if dt % 2 != 0:
                    try:
                        dt_inv = pow(dt, -1, mod)
                        d_mod = (du * dt_inv) % mod
                        d_mod_counts[d_mod] += 1
                        pair_count += 1
                    except: pass
                
                if pair_count >= max_pairs: break
            if pair_count >= max_pairs: break
            
        if not d_mod_counts: continue
        
        most_common = d_mod_counts.most_common(1)[0]
        ratio = most_common[1] / pair_count if pair_count > 0 else 0
        
        # Expected ratio for random is 1/mod
        # We look for something significantly higher
        if ratio > (3.0 / mod) and most_common[1] > 10:
            print(f"!!! FOUND LSB BIAS at {b} bits !!!")
            print(f"    d mod {mod} = {most_common[0]} (count={most_common[1]}, ratio={ratio:.4f}, expected={1/mod:.4f})")
            results.append({'bits': b, 'd_mod': most_common[0], 'ratio': ratio})
            
    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 check_lsb_system.py <sigs.json>")
    else:
        with open(sys.argv[1], "r") as f:
            sigs = json.load(f)
        check_lsb_system(sigs)
