import json
import sys

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def check_lsb_system(filename):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    print(f"Checking for LSB system bias in {len(sigs)} sigs...")
    
    u_vals = []
    t_vals = []
    for s in sigs:
        s_inv = pow(s['s'], -1, P)
        u_vals.append((s_inv * s['z']) % P)
        t_vals.append((s_inv * s['r']) % P)
        
    for b in range(1, 17):
        mod = 1 << b
        
        # For each possible d_mod, count occurrences of a_mod = (t_i * d_mod + u_i) % mod
        best_count = 0
        best_d = 0
        best_a = 0
        
        for d_mod in range(mod):
            a_counts = {}
            for i in range(len(sigs)):
                a_mod = (t_vals[i] * d_mod + u_vals[i]) % mod
                a_counts[a_mod] = a_counts.get(a_mod, 0) + 1
            
            for a_mod, count in a_counts.items():
                if count > best_count:
                    best_count = count
                    best_d = d_mod
                    best_a = a_mod
        
        if best_count >= len(sigs) * 0.7:
            print(f"!!! BIAS DETECTED at b={b} !!!")
            print(f"    Best (d mod {mod}, a mod {mod}) = ({best_d}, {best_a}) ({best_count}/{len(sigs)})")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 check_lsb_system.py <sigs.json>")
    else:
        check_lsb_system(sys.argv[1])
