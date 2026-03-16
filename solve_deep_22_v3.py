import sqlite3
import collections
import json
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key

P = SECP256k1.order

def solve():
    address = "1FdPpELnjHfwSM4Nvi7LdYS4S4GVGsLUQY"
    bits = 22
    d_mod = 1073387
    mod = 1 << bits
    
    with open('sigs_1FdPpELn.json', 'r') as f:
        sigs = json.load(f)
        
    prepared = []
    for s in sigs:
        s_inv = pow(s['s'], -1, P)
        u = (s_inv * s['z']) % P
        t = (s_inv * s['r']) % P
        a_k = (u + t * d_mod) % mod
        prepared.append({'u': u, 't': t, 'a_k': a_k, 'r': s['r'], 's': s['s'], 'z': s['z']})
        
    counts = collections.Counter([p['a_k'] for p in prepared])
    print(f"Top a_k counts: {counts.most_common(5)}")
    
    best_sigs = [p for p in prepared if counts[p['a_k']] >= 3]
    print(f"Total biased signatures found: {len(best_sigs)}")
    
    # Limit to 40 for speed
    best_sigs = best_sigs[:40]
    print(f"Using {len(best_sigs)} biased signatures for LLL.")
    
    # Standard HNP with n sigs
    n = len(best_sigs)
    B = 1 << (256 - bits)
    inv_2b = pow(mod, -1, P)
    
    matrix = [[0] * (n + 2) for _ in range(n + 2)]
    for i in range(n):
        # EACH sig has its own a_k
        u_p = ((best_sigs[i]['u'] + best_sigs[i]['t'] * d_mod - best_sigs[i]['a_k']) * inv_2b) % P
        t_p = best_sigs[i]['t']
        matrix[i][i] = P
        matrix[n][i] = t_p
        matrix[n+1][i] = u_p
        
    matrix[n][n] = 1
    matrix[n+1][n+1] = B
    
    from fast_lll import fast_lll
    print("Starting LLL reduction...")
    reduced = fast_lll(matrix)
    print("LLL reduction complete.")
    
    for row in reduced:
        d_prime = abs(int(row[n]))
        for dp in [d_prime, (P - d_prime) % P]:
            if dp == 0: continue
            d = (dp * mod + d_mod) % P
            if verify_key(d, address):
                print(f"!!! SUCCESS !!! Private key found: {hex(d)}")
                return d
    
    print("Failed to find key.")

if __name__ == "__main__":
    solve()
