import json
import sys
import multiprocessing as mp
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key, lll_reduction

P = SECP256k1.order
address = "1GR9qNz7zgtaW5HwwVpEJWMnGWhsbsieCG"

def check_range(start, end, mod, a_val, sig0, address):
    for kp in range(start, end):
        k = (mod * kp + a_val) % P
        # d = (s*k - z)/r
        d = ((sig0['s'] * k - sig0['z']) * pow(sig0['r'], -1, P)) % P
        if verify_key(d, address):
            return d
    return None

def solve_1GR9qNz7(sigs_file, bias_bits, a_val):
    with open(sigs_file, "r") as f:
        sigs = json.load(f)
    
    if not sigs:
        print("No signatures found.")
        return
        
    print(f"Solving 1GR9qNz7 with {len(sigs)} sigs, {bias_bits} bits, a={a_val}...")
    
    mod = 1 << bias_bits
    
    print("Trying small k' for 1-sig case (Parallel)...")
    num_procs = mp.cpu_count()
    chunk = 20000000 # 20M per process
    
    with mp.Pool(num_procs) as pool:
        results = []
        for i in range(num_procs):
            results.append(pool.apply_async(check_range, (i * chunk, (i + 1) * chunk, mod, a_val, sigs[0], address)))
        
        for r in results:
            d = r.get()
            if d:
                print(f"!!! SUCCESS !!! Private key found for {address}")
                print(f"d = {hex(d)}")
                return d
            
    print("Small k' failed.")
    return None

if __name__ == "__main__":
    solve_1GR9qNz7('sigs_1GR9qNz7.json', 12, 623)
