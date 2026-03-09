import json
import sys

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def detect_nonce_lsb_bias(filename):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    print(f"Checking for Nonce LSB bias in {len(sigs)} sigs...")
    
    for b in range(1, 17):
        mod = 1 << b
        d_mod_counts = {}
        for s in sigs:
            try:
                # k = u + d*t (mod P)
                # If k = 0 (mod mod), then d*t = -u (mod mod)
                # d = -u * t_inv (mod mod)
                
                # Note: This only works if t is invertible mod 2^b (i.e., t is odd)
                # If t is even, we have to be more careful, but for now let's just skip.
                
                u = (pow(s['s'], -1, P) * s['z']) % P
                t = (pow(s['s'], -1, P) * s['r']) % P
                
                # Check if t is odd
                if t % 2 == 0: continue
                
                t_inv_mod = pow(t, -1, mod)
                d_mod = ((-u) * t_inv_mod) % mod
                d_mod_counts[d_mod] = d_mod_counts.get(d_mod, 0) + 1
            except: pass
        
        if not d_mod_counts: continue
        
        # Check for any d_mod that occurs frequently
        max_count = max(d_mod_counts.values())
        if max_count >= len(sigs) * 0.7 and len(sigs) >= 2:
            best_d_mod = [k for k, v in d_mod_counts.items() if v == max_count][0]
            print(f"!!! Potential Nonce LSB bias (k=0 mod {mod}) detected !!!")
            print(f"    Possible d mod {mod} = {best_d_mod} ({max_count}/{len(sigs)} sigs)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 detect_nonce_lsb_bias.py <sigs.json>")
    else:
        detect_nonce_lsb_bias(sys.argv[1])
