import json
import collections
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key
from fast_lll import fast_lll

P = SECP256k1.order

def solve():
    import sqlite3
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    cur.execute("SELECT address FROM signatures WHERE address LIKE 'bc1ql5hl%' LIMIT 1")
    full_address = cur.fetchone()[0]
    conn.close()
    
    print(f"Targeting address: {full_address}")
    
    bits = 12
    d_mod = 3094
    mod = 1 << bits
    
    with open('sigs_bc1ql5hl.json', 'r') as f:
        sigs = json.load(f)
        
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
        
    a_k_counts = collections.Counter([p['a_k'] for p in prepared])
    print(f"Top a_k counts: {a_k_counts.most_common(5)}")
    
    best_sigs = [p for p in prepared if a_k_counts[p['a_k']] >= 2]
    print(f"Found {len(best_sigs)} signatures in groups of >= 2.")
    
    if len(best_sigs) < 10:
        best_sigs = prepared[:40]
        
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
    
    print(f"Running LLL on {n+2}x{n+2} matrix...")
    reduced = fast_lll(matrix)
    
    for row in reduced:
        d_prime = abs(int(row[n]))
        for dp in [d_prime, (P - d_prime) % P]:
            if dp == 0: continue
            d = (dp * mod + d_mod) % P
            if verify_key(d, full_address):
                print(f"!!! SUCCESS !!! Private key found: {hex(d)}")
                return d
    
    print("Failed.")

if __name__ == "__main__":
    solve()
