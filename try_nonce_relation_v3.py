import json
import sys
from lattice_nonce_analyzer import verify_key

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def try_nonce_relation(filename, address):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    n = len(sigs)
    print(f"Checking for Nonce Relations (k_i = (a/b) * k_j) in {n} sigs...")
    
    limit = 10 # Reduced limit slightly for speed, but can be increased
    
    for i in range(n):
        if i % 5 == 0: print(f"Processing sig {i}/{n}...")
        s1_data = sigs[i]
        r1, s1, z1 = s1_data['r'], s1_data['s'], s1_data['z']
        
        for j in range(i + 1, n):
            s2_data = sigs[j]
            r2, s2, z2 = s2_data['r'], s2_data['s'], s2_data['z']
            
            # Precompute products for inner loop
            s1_z2 = (s1 * z2) % P
            s2_z1 = (s2 * z1) % P
            s2_r1 = (s2 * r1) % P
            s1_r2 = (s1 * r2) % P

            for a in range(1, limit + 1):
                a_s1_z2 = (a * s1_z2) % P
                a_s1_r2 = (a * s1_r2) % P
                for b in range(1, limit + 1):
                    if a == 1 and b == 1: continue
                    
                    num = (a_s1_z2 - b * s2_z1) % P
                    den = (b * s2_r1 - a_s1_r2) % P
                    
                    if den != 0:
                        d = (num * pow(den, -1, P)) % P
                        if verify_key(d, address):
                            print(f"!!! SUCCESS !!! Nonce relation found: k_{i} = ({a}/{b}) * k_{j}")
                            print(f"Private Key: {hex(d)}")
                            return d
    print("No nonce relation found.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 try_nonce_relation_v3.py <sigs.json> <address>")
    else:
        try_nonce_relation(sys.argv[1], sys.argv[2])
