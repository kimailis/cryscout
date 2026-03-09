import json
import sys
from collections import Counter

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def find_full_lsb_bias(filename):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    n = len(sigs)
    print(f"Deep checking for LSB bias in {n} sigs...")
    
    for b in range(1, 17):
        mod = 1 << b
        # Try all possible k_fixed values mod 2^b
        for k_fixed in range(mod):
            d_candidates = []
            for i in range(n):
                s1 = sigs[i]
                # k1 = k1' * 2^b + k_fixed
                # d * r1 = s1 * (k1' * 2^b + k_fixed) - z1
                # d * r1 = s1 * k_fixed - z1 (mod 2^b)
                r1 = s1['r']
                s1_val = s1['s']
                z1 = s1['z']
                
                rhs = (s1_val * k_fixed - z1) % mod
                
                # Solve d * r1 = rhs (mod mod)
                # If r1 is odd, we can solve it.
                if r1 % 2 != 0:
                    d_mod = (rhs * pow(r1, -1, mod)) % mod
                    d_candidates.append(d_mod)
            
            if not d_candidates: continue
            
            counts = Counter(d_candidates)
            best_d_mod, count = counts.most_common(1)[0]
            if count >= len(sigs) * 0.8: # Strong bias
                print(f"!!! STRONG BIAS FOUND !!!")
                print(f"Bits: {b} | k_fixed: {k_fixed} | Possible d mod {mod} = {best_d_mod} ({count}/{len(sigs)} sigs)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 find_full_lsb_bias.py <sigs.json>")
    else:
        find_full_lsb_bias(sys.argv[1])
