import json
import sys
import collections
from ecdsa import SECP256k1

P = SECP256k1.order

def find_clique(sigs, d_mod, bits):
    mod = 1 << bits
    prepared = []
    for i, s in enumerate(sigs):
        try:
            s_inv = pow(s['s'], -1, P)
            u = (s_inv * s['z']) % P
            t = (s_inv * s['r']) % P
            prepared.append({'i': i, 'u': u, 't': t})
        except: continue
        
    matching_sigs = set()
    pair_count = 0
    
    for i in range(len(prepared)):
        for j in range(i + 1, len(prepared)):
            dt = (prepared[i]['t'] - prepared[j]['t']) % mod
            du = (prepared[j]['u'] - prepared[i]['u']) % mod
            
            if dt % 2 != 0:
                try:
                    dt_inv = pow(dt, -1, mod)
                    current_d_mod = (du * dt_inv) % mod
                    if current_d_mod == d_mod:
                        matching_sigs.add(prepared[i]['i'])
                        matching_sigs.add(prepared[j]['i'])
                        pair_count += 1
                except: pass
                
    print(f"Found {len(matching_sigs)} signatures forming {pair_count} pairs for d mod {mod} = {d_mod}")
    print(f"Signature indices: {sorted(list(matching_sigs))}")
    
    # Check if these sigs have a HIGHER bias together
    if len(matching_sigs) >= 2:
        sub_sigs = [sigs[i] for i in matching_sigs]
        # Re-run prepared for sub_sigs
        sub_prep = []
        for s in sub_sigs:
            s_inv = pow(s['s'], -1, P)
            sub_prep.append({'u': (s_inv * s['z']) % P, 't': (s_inv * s['r']) % P})
            
        for b in range(bits + 1, 257):
            m = 1 << b
            d_counts = collections.Counter()
            pc = 0
            for i in range(len(sub_prep)):
                for j in range(i + 1, len(sub_prep)):
                    dt = (sub_prep[i]['t'] - sub_prep[j]['t']) % m
                    du = (sub_prep[j]['u'] - sub_prep[i]['u']) % m
                    if dt % 2 != 0:
                        try:
                            d_counts[(du * pow(dt, -1, m)) % m] += 1
                            pc += 1
                        except: pass
            
            if not d_counts: break
            most_common = d_counts.most_common(1)[0]
            if most_common[1] == pc and pc > 0:
                print(f"  All pairs match d mod 2^{b} = {most_common[0]}")
            else:
                print(f"  Bias broken at {b} bits")
                break

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 find_lsb_clique.py <sigs.json> <d_mod> <bits>")
    else:
        with open(sys.argv[1], "r") as f:
            sigs = json.load(f)
        find_clique(sigs, int(sys.argv[2]), int(sys.argv[3]))
