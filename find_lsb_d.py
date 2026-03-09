import json
import sys
from collections import Counter

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def find_lsb_d(filename):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    n = len(sigs)
    print(f"Checking for LSB bias in {n} sigs...")
    
    for b in range(1, 17):
        mod = 1 << b
        d_candidates = []
        for i in range(n):
            s1 = sigs[i]
            u1 = (pow(s1['s'], -1, P) * s1['z']) % P
            t1 = (pow(s1['s'], -1, P) * s1['r']) % P
            
            for j in range(i + 1, n):
                s2 = sigs[j]
                u2 = (pow(s2['s'], -1, P) * s2['z']) % P
                t2 = (pow(s2['s'], -1, P) * s2['r']) % P
                
                # d * (t1 - t2) = u2 - u1 (mod mod)
                dt = (t1 - t2) % mod
                du = (u2 - u1) % mod
                
                # Solve dt * d = du (mod mod)
                # This only works if dt is invertible mod mod (i.e., dt is odd)
                if dt % 2 != 0:
                    d_mod = (du * pow(dt, -1, mod)) % mod
                    d_candidates.append(d_mod)
        
        if not d_candidates: continue
        
        counts = Counter(d_candidates)
        best_d_mod, count = counts.most_common(1)[0]
        if count > len(d_candidates) * 0.1: # Significant bias
             print(f"Bits: {b} | Possible d mod {mod} = {best_d_mod} ({count}/{len(d_candidates)} pairs)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 find_lsb_d.py <sigs.json>")
    else:
        find_lsb_d(sys.argv[1])
