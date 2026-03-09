import json
import sys
from lattice_nonce_analyzer import verify_key

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def try_nonce_relation(filename, address):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    print(f"Checking for Nonce Relations (k_i = c * k_j) in {len(sigs)} sigs...")
    
    for i in range(len(sigs)):
        for j in range(i + 1, len(sigs)):
            s1, s2 = sigs[i], sigs[j]
            for c in range(1, 100):
                # Try c and 1/c
                for val_c in [c, pow(c, -1, P)]:
                    # d = (s1*val_c*z2 - s2*z1) * (s2*r1 - s1*val_c*r2)^-1
                    num = (s1['s'] * val_c * s2['z'] - s2['s'] * s1['z']) % P
                    den = (s2['s'] * s1['r'] - s1['s'] * val_c * s2['r']) % P
                    
                    if den != 0:
                        d = (num * pow(den, -1, P)) % P
                        if verify_key(d, address):
                            print(f"!!! SUCCESS !!! Nonce relation found: k_{i} = {val_c} * k_{j}")
                            print(f"Private Key: {hex(d)}")
                            return d
    print("No simple nonce relation found.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 try_nonce_relation.py <sigs.json> <address>")
    else:
        try_nonce_relation(sys.argv[1], sys.argv[2])
