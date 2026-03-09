import json
import os

def check_segwit_sigs():
    files = ["sigs_bc1ql5hl.json", "sigs_bc1ql5hl_100.json"]
    r_map = {}
    
    for filename in files:
        if not os.path.exists(filename): continue
        with open(filename, "r") as f:
            sigs = json.load(f)
            for s in sigs:
                r = s['r']
                if r not in r_map: r_map[r] = []
                r_map[r].append(s)
                
    for r, items in r_map.items():
        if len(items) > 1:
            # Check if any Z are different
            z_vals = set(it['z'] for it in items)
            if len(z_vals) > 1:
                print(f"!!! SOLVABLE REUSE FOUND for bc1ql5hl !!!")
                print(f"R: {hex(r)}")
                print(f"Z count: {len(z_vals)}")
                return True
    print("No solvable reuse found in JSON files.")
    return False

if __name__ == "__main__":
    check_segwit_sigs()
