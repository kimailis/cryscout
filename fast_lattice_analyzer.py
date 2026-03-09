import json
import sys
from lattice_nonce_analyzer import solve_hnp, verify_key

def fast_lattice(filename, address, max_sigs=10):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    # Use only max_sigs for speed
    if len(sigs) > max_sigs:
        sigs = sigs[:max_sigs]
    
    print(f"Loaded {len(sigs)} sigs from {filename}")
    
    # Try bias_bits from 4 to 128 (no need for 1-3 bits as they're unlikely to work with only 10 sigs)
    # Actually, for 10 sigs, we need at least 256/10 = 26 bits of bias.
    for b in range(4, 256, 4):
        print(f"Trying bias_bits={b}...")
        key = solve_hnp(sigs, b, address=address)
        if key:
            print(f"!!! SUCCESS at bias_bits={b} !!!")
            print(f"Private Key: {hex(key)}")
            return key
    print("No key found.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 fast_lattice_analyzer.py <json_file> <address> [max_sigs]")
    else:
        max_sigs = int(sys.argv[3]) if len(sys.argv) > 3 else 10
        fast_lattice(sys.argv[1], sys.argv[2], max_sigs)
