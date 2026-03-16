import json
import collections
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key
from fast_lll import fast_lll

P = SECP256k1.order

def solve():
    address = "1FdPpELnjHfwSM4Nvi7LdYS4S4GVGsLUQY"
    bits = 22
    d_mod = 1073387
    mod = 1 << bits
    
    with open('sigs_1FdPpELn.json', 'r') as f:
        sigs = json.load(f)
        
    # Get unique signatures based on (r, s)
    unique_sigs = {}
    for s in sigs:
        unique_sigs[(s['r'], s['s'])] = s
    
    prepared = []
    for (r, s), sig in unique_sigs.items():
        s_inv = pow(sig['s'], -1, P)
        u = (s_inv * sig['z']) % P
        t = (s_inv * sig['r']) % P
        a_k = (u + t * d_mod) % mod
        prepared.append({'u': u, 't': t, 'a_k': a_k, 'r': r, 's': s, 'z': sig['z']})
        
    print(f"Total unique signatures: {len(prepared)}")
    
    # We suspect d_mod = 1073387 is correct for SOME signatures.
    # Let's try to use signatures that share the same a_k if any.
    a_k_counts = collections.Counter([p['a_k'] for p in prepared])
    print(f"Top a_k counts (unique sigs): {a_k_counts.most_common(5)}")
    
    # Use the top 60 signatures? 
    # Actually, we don't know which ones are biased. 
    # But if d_mod is correct, then ANY signature with a fixed k_low should work.
    # Let's just use the first 60.
    best_sigs = prepared[:60]
    print(f"Using {len(best_sigs)} unique signatures for LLL.")
    
    n = len(best_sigs)
    B = 1 << (256 - bits)
    inv_2b = pow(mod, -1, P)
    
    matrix = [[0] * (n + 2) for _ in range(n + 2)]
    for i in range(n):
        u_p = ((best_sigs[i]['u'] + best_sigs[i]['t'] * d_mod - best_sigs[i]['a_k']) * inv_2b) % P
        t_p = best_sigs[i]['t']
        matrix[i][i] = P
        matrix[n][i] = t_p
        matrix[n+1][i] = u_p
        
    matrix[n][n] = 1
    matrix[n+1][n+1] = B
    
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
