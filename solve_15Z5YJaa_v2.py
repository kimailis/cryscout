import json
import sys
import mpmath
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key
from offline_lattice_analyzer_mpmath import lll_reduction_mp

P = SECP256k1.order
address = "15Z5YJaaNSxeynvr6uW6jQZLwq3n1Hu6RX"

def solve():
    with open('sigs_15Z5YJaa_all.json', 'r') as f:
        sigs = json.load(f)
    
    # Based on check_lsb_all.py results:
    # d mod 2048 = 863 (11 bits)
    bits = 11
    d_mod = 863
    mod = 1 << bits
    inv_mod = pow(mod, -1, P)
    
    prepared = []
    for s in sigs:
        try:
            s_inv = pow(s['s'], -1, P)
            u = (s_inv * s['z']) % P
            t = (s_inv * s['r']) % P
            # k = 2^b * k' + a
            # For each sig, there's some a = (u + t*d_mod) % mod
            a = (u + t * d_mod) % mod
            u_prime = ((u + t * d_mod - a) * inv_mod) % P
            t_prime = t
            prepared.append({'u': u_prime, 't': t_prime})
        except: continue

    n = min(len(prepared), 30)
    B = 1 << (256 - bits)
    
    matrix = [[mpmath.mpf(0)] * (n + 2) for _ in range(n + 2)]
    for i in range(n): matrix[i][i] = mpmath.mpf(P)
    for i in range(n): matrix[n][i] = mpmath.mpf(prepared[i]['t'])
    matrix[n][n] = mpmath.mpf(1)
    for i in range(n): matrix[n+1][i] = mpmath.mpf(prepared[i]['u'])
    matrix[n+1][n+1] = mpmath.mpf(B)
    
    print(f"Running high-precision LLL with {n} sigs and {bits} bits bias...")
    reduced = lll_reduction_mp(matrix)
    
    print("Shortest vectors (log2):")
    for i in range(min(5, len(reduced))):
        length = mpmath.sqrt(sum(x**2 for x in reduced[i]))
        print(f"  v{i}: {mpmath.log(length, 2)}")

    for row in reduced:
        potential_d_prime = abs(int(row[n]))
        if potential_d_prime == 0 or potential_d_prime >= P: continue
        d = (potential_d_prime * mod + d_mod) % P
        if verify_key(d, address):
            print(f"!!! SUCCESS !!! Private key: {hex(d)}")
            return d
        d_neg = ((-potential_d_prime % P) * mod + d_mod) % P
        if verify_key(d_neg, address):
            print(f"!!! SUCCESS !!! Private key (neg): {hex(d_neg)}")
            return d_neg
    print("Failed.")

if __name__ == "__main__":
    solve()
