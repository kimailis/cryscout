import json
import sys
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key

P = SECP256k1.order

def solve_with_offset(sigs, address, offset_range=1000):
    print(f"Checking for k_i = k_j + delta in {len(sigs)} sigs...")
    
    prep = []
    for s in sigs:
        s_inv = pow(s['s'], -1, P)
        prep.append({'u': (s_inv * s['z']) % P, 't': (s_inv * s['r']) % P})
        
    for i in range(len(prep)):
        for j in range(i + 1, len(prep)):
            p1, p2 = prep[i], prep[j]
            dt = (p1['t'] - p2['t']) % P
            if dt == 0: continue
            dt_inv = pow(dt, -1, P)
            
            for delta in range(-offset_range, offset_range + 1):
                # k1 = k2 + delta
                # u1 + t1*d = u2 + t2*d + delta
                # d * (t1 - t2) = u2 - u1 + delta
                d = ((p2['u'] - p1['u'] + delta) * dt_inv) % P
                if verify_key(d, address):
                    print(f"!!! SUCCESS !!! Key found for {address}: {hex(d)}")
                    return d
    print("Done.")

if __name__ == "__main__":
    target = "15Z5YJaaNSxeynvr6uW6jQZLwq3n1Hu6RX"
    with open('sigs_15Z5YJaa_all.json', 'r') as f:
        sigs = json.load(f)
    solve_with_offset(sigs, target)
