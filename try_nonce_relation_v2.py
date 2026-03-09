import json
import sys
from lattice_nonce_analyzer import verify_key

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def try_nonce_relation(filename, address):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    print(f"Checking for Nonce Relations (k_i = (a/b) * k_j) in {len(sigs)} sigs...")
    
    # We test ratios a/b where a, b are small integers
    # k_i = (a/b) * k_j  =>  b * k_i = a * k_j
    # s1 = (z1 + r1*d)/k1  => k1 = (z1 + r1*d)/s1
    # s2 = (z2 + r2*d)/k2  => k2 = (z2 + r2*d)/s2
    # b * (z1 + r1*d)/s1 = a * (z2 + r2*d)/s2
    # b * s2 * (z1 + r1*d) = a * s1 * (z2 + r2*d)
    # b*s2*z1 + b*s2*r1*d = a*s1*z2 + a*s1*r2*d
    # d * (b*s2*r1 - a*s1*r2) = a*s1*z2 - b*s2*z1
    # d = (a*s1*z2 - b*s2*z1) / (b*s2*r1 - a*s1*r2)

    limit = 20 # Try all ratios a/b with a, b up to 20
    
    for i in range(len(sigs)):
        if i % 10 == 0: print(f"Processing sig {i}...")
        for j in range(i + 1, len(sigs)):
            s1_data, s2_data = sigs[i], sigs[j]
            r1, s1, z1 = s1_data['r'], s1_data['s'], s1_data['z']
            r2, s2, z2 = s2_data['r'], s2_data['s'], s2_data['z']
            
            for a in range(1, limit + 1):
                for b in range(1, limit + 1):
                    # Skip 1/1 as it is R-reuse (already checked)
                    if a == 1 and b == 1: continue
                    
                    num = (a * s1 * z2 - b * s2 * z1) % P
                    den = (b * s2 * r1 - a * s1 * r2) % P
                    
                    if den != 0:
                        d = (num * pow(den, -1, P)) % P
                        if verify_key(d, address):
                            print(f"!!! SUCCESS !!! Nonce relation found: k_{i} = ({a}/{b}) * k_{j}")
                            print(f"Private Key: {hex(d)}")
                            return d
    print("No nonce relation found with small integer ratios.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 try_nonce_relation_v2.py <sigs.json> <address>")
    else:
        try_nonce_relation(sys.argv[1], sys.argv[2])
