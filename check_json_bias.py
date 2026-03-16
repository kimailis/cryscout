import json
from collections import Counter
import math

def check_bias(file_path):
    with open(file_path, 'r') as f:
        sigs = json.load(f)
    
    print(f"[*] Analyzing {len(sigs)} signatures from {file_path}...")
    
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    lsb_counts = Counter()
    msb_counts = Counter()
    
    for s in sigs:
        r = int(s['r'])
        lsb_counts[r & 0xFF] += 1
        msb_counts[r >> 248] += 1
        
    print("\n[+] LSB (last 8 bits) distribution (top 10):")
    for val, count in lsb_counts.most_common(10):
        print(f"  0x{val:02x}: {count}")
        
    print("\n[+] MSB (first 8 bits) distribution (top 10):")
    for val, count in msb_counts.most_common(10):
        print(f"  0x{val:02x}: {count}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 check_json_bias.py <sigs.json>")
    else:
        check_bias(sys.argv[1])
