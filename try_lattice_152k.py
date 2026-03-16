import sqlite3
import collections
import json
import mpmath
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key
from fast_lll import fast_lll

P = SECP256k1.order
mpmath.mp.prec = 512

def solve():
    address = "152kzDqjAVuPBMmJqcWvFbB7qkvigFXSLh"
    bits = 12
    d_mod = 2841
    mod = 1 << bits
    
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    cur.execute('SELECT r_int, s_int, z_int FROM signatures WHERE address = ?', (address,))
    rows = cur.fetchall()
    conn.close()
    
    unique_sigs = {}
    for r, s, z in rows:
        unique_sigs[(int(r), int(s))] = int(z)
        
    prepared = []
    for (r, s), z in unique_sigs.items():
        s_inv = pow(s, -1, P)
        u = (s_inv * z) % P
        t = (s_inv * r) % P
        a_k = (u + t * d_mod) % mod
        prepared.append({'u': u, 't': t, 'a_k': a_k, 'r': r, 's': s})
        
    counts = collections.Counter([p['a_k'] for p in prepared])
    best_ak = counts.most_common(1)[0][0]
    target_sigs = [p for p in prepared if p['a_k'] == best_ak]
    
    print(f"Targeting {address} | bits={bits} | d_mod={d_mod}")
    print(f"Using {len(target_sigs)} sigs with a_k={best_ak}")
    
    if len(target_sigs) < 4:
        # Not enough collisions for a high-confidence attack, but let's try more sigs
        # Maybe many share the same d_mod but have different a_ks?
        # Let's try the top 2 groups
        top_2_aks = [ak for ak, count in counts.most_common(2)]
        target_sigs = [p for p in prepared if p['a_k'] in top_2_aks]
        print(f"Using {len(target_sigs)} sigs from top 2 groups.")

    n = len(target_sigs)
    B = 1 << (256 - bits)
    inv_2b = pow(mod, -1, P)
    
    matrix = [[0] * (n + 2) for _ in range(n + 2)]
    for i in range(n):
        u_p = ((target_sigs[i]['u'] + target_sigs[i]['t'] * d_mod - target_sigs[i]['a_k']) * inv_2b) % P
        t_p = target_sigs[i]['t']
        matrix[i][i] = P
        matrix[n][i] = t_p
        matrix[n+1][i] = u_p
        
    matrix[n][n] = 1
    matrix[n+1][n+1] = B
    
    reduced = fast_lll(matrix)
    
    for row in reduced:
        d_prime = abs(int(row[n]))
        for dp in [d_prime, (P - d_prime) % P]:
            if dp == 0: continue
            d = (dp * mod + d_mod) % P
            if verify_key(d, address):
                print(f"!!! SUCCESS !!! Private key found: {hex(d)}")
                return d
    print("Failed.")

if __name__ == "__main__":
    solve()
