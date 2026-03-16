import sqlite3
import collections
import json
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key, lll_reduction

P = SECP256k1.order

def solve_deep_bias():
    address = "1FdPpELnjHfwSM4Nvi7LdYS4S4GVGsLUQY"
    bits = 20
    d_mod = 911798
    
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    cur.execute('SELECT r_int, s_int, z_int, txid FROM signatures WHERE address = ?', (address,))
    rows = cur.fetchall()
    
    mod = 1 << bits
    sigs = []
    for r, s, z, txid in rows:
        r, s, z = int(r), int(s), int(z)
        s_inv = pow(s, -1, P)
        # a_k = (u + t*d) % mod
        u = (s_inv * z) % P
        t = (s_inv * r) % P
        a_k = (u + t * d_mod) % mod
        sigs.append({'a_k': a_k, 'r': r, 's': s, 'z': z, 'u': u, 't': t, 'txid': txid})
    
    counts = collections.Counter([s['a_k'] for s in sigs])
    # Get signatures from groups with count >= 3
    biased_sigs = [s for s in sigs if counts[s['a_k']] >= 3]
    
    print(f"Found {len(biased_sigs)} biased signatures in groups of >= 3.")
    
    if len(biased_sigs) < 4:
        print("Not enough biased signatures.")
        return

    # Limit to 15 sigs for performance
    target_sigs = biased_sigs[:15]
    n = len(target_sigs)
    
    # Construction: k'_i = u'_i + t'_i * d' (mod P)
    # k'_i - t'_i * d' = u'_i (mod P)
    # k'_i < P/2^bits, d' < P/2^bits
    
    inv_2b = pow(mod, -1, P)
    u_primes = []
    t_primes = []
    for s in target_sigs:
        # u'_i = (u_i + t_i * d_mod - a_{k,group}) * (2^b)^{-1} % P
        u_p = ((s['u'] + s['t'] * d_mod - s['a_k']) * inv_2b) % P
        t_p = s['t']
        u_primes.append(u_p)
        t_primes.append(t_p)
    
    print(f"u_primes[0]: {hex(u_primes[0])}")
    print(f"t_primes[0]: {hex(t_primes[0])}")
        
    # Lattice matrix
    # [ P  0  0 ... 0  0 ]
    # [ 0  P  0 ... 0  0 ]
    # [ ...              ]
    # [ t1 t2 t3... 1  0 ]
    # [ u1 u2 u3... 0  1 ]
    
    B = 1 
    matrix = [[0] * (n + 2) for _ in range(n + 2)]
    for i in range(n):
        matrix[i][i] = P
        matrix[n][i] = t_primes[i]
        matrix[n+1][i] = u_primes[i]
    
    matrix[n][n] = 1 # unknown d'
    matrix[n+1][n+1] = B
    
    print(f"Running LLL reduction on {n+2}x{n+2} matrix...")
    reduced = lll_reduction(matrix)
    
    print(f"Checking {len(reduced)} rows for d'...")
    for row in reduced:
        # The (n)th element is d'
        d_prime = abs(int(row[n]))
        if d_prime == 0 or d_prime >= P: continue
        
        # d = d' * 2^bits + d_mod
        potential_d = (d_prime * mod + d_mod) % P
        if verify_key(potential_d, address):
            print(f"!!! SUCCESS !!! Private key found for {address}")
            print(f"d = {hex(potential_d)}")
            return potential_d
            
        # Try P - d_prime just in case
        d_prime = P - d_prime
        potential_d = (d_prime * mod + d_mod) % P
        if verify_key(potential_d, address):
            print(f"!!! SUCCESS !!! Private key found for {address}")
            print(f"d = {hex(potential_d)}")
            return potential_d

    print("Lattice attack failed to find the key.")
    return None

if __name__ == "__main__":
    solve_deep_bias()
