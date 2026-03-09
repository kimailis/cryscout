import json
import sys
from lattice_nonce_analyzer import verify_key

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def try_nonce_delta(filename, address):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    print(f"Checking for Nonce Deltas (k_i = k_j + delta) in {len(sigs)} sigs...")
    
    for i in range(len(sigs)):
        for j in range(i + 1, len(sigs)):
            s1, s2 = sigs[i], sigs[j]
            for delta in range(-100, 101):
                # d = (s1*s2*delta + s1*z2 - s2*z1) * (s2*r1 - s1*r2)^-1
                num = (s1['s'] * s2['s'] * delta + s1['s'] * s2['z'] - s2['s'] * s1['z']) % P
                den = (s2['s'] * s1['r'] - s1['s'] * s2['r']) % P
                
                if den != 0:
                    d = (num * pow(den, -1, P)) % P
                    if verify_key(d, address):
                        print(f"!!! SUCCESS !!! Nonce delta found: k_{i} = k_{j} + {delta}")
                        print(f"Private Key: {hex(d)}")
                        return d
    print("No simple nonce delta found.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 try_nonce_delta.py <sigs.json> <address>")
    else:
        try_nonce_delta(sys.argv[1], sys.argv[2])
