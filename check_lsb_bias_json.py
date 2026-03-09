import json
import sys

def check_lsb_bias_json(filename):
    with open(filename, 'r') as f:
        sigs = json.load(f)
    
    r_values = [sig['r'] for sig in sigs]
    print(f"Analyzing {len(r_values)} R-values from {filename}...")
    
    for i in range(1, 17):
        mod = 1 << i
        counts = {}
        for r in r_values:
            val = r % mod
            counts[val] = counts.get(val, 0) + 1
        
        # Check if any value is suspiciously frequent
        found = False
        for val, count in counts.items():
            if count > len(r_values) * 0.5:
                print(f"!!! Potential LSB bias at bits 0-{i-1}: r % {mod} == {val} ({count}/{len(r_values)}) !!!")
                found = True
        if not found:
            # print(f"No strong bias at {i} bits.")
            pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 check_lsb_bias_json.py <sigs.json>")
    else:
        check_lsb_bias_json(sys.argv[1])
