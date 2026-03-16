import json
import sys
import collections
import mpmath
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key, lll_reduction

P = SECP256k1.order
address = "15Z5YJaaNSxeynvr6uW6jQZLwq3n1Hu6RX"

def solve_15Z5YJaa(sigs_file, d_mod, bits):
    with open(sigs_file, "r") as f:
        sigs = json.load(f)
    
    mod = 1 << bits
    inv_mod = pow(mod, -1, P)
    
    # 1. Group sigs by their 'a' value
    prepared = []
    for i, s in enumerate(sigs):
        try:
            s_inv = pow(s['s'], -1, P)
            u = (s_inv * s['z']) % P
            t = (s_inv * s['r']) % P
            a = (u + t * d_mod) % mod
            
            # Equation: k' = t*d' + u'
            # u' = (u + t*d_mod - a) / mod
            # t' = t (stays same)
            # Wait, no. k = 2^b * k' + a
            # 2^b * k' + a = u*s + t*s*d = z + r*d
            # 2^b * k' + a = z*s_inv + r*s_inv*(2^b * d' + d_mod)
            # 2^b * k' + a = u + t*(2^b * d' + d_mod)
            # 2^b * k' = u + t*d_mod - a + t*2^b * d'
            # k' = (u + t*d_mod - a)*inv_mod + t*d'
            
            u_prime = ((u + t * d_mod - a) * inv_mod) % P
            t_prime = t
            prepared.append({'u': u_prime, 't': t_prime})
        except: continue
        
    print(f"Prepared {len(prepared)} equations for d' recovery.")
    
    # 2. Solve HNP for d'
    # Use 20 sigs for a better balance between info and LLL speed
    n = 20
    if len(prepared) < n:
        n = len(prepared)
    B = 1 << (256 - bits)

    matrix = [[0] * (n + 2) for _ in range(n + 2)]
    for i in range(n): matrix[i][i] = P
    for i in range(n): matrix[n][i] = prepared[i]['t']
    matrix[n][n] = 1 
    for i in range(n): matrix[n+1][i] = prepared[i]['u']
    matrix[n+1][n+1] = B

    print(f"Running LLL reduction with {n} sigs...")
    reduced = lll_reduction(matrix)

    print("Top 5 shortest vector lengths (log2):")
    for i in range(min(5, len(reduced))):
        length = mpmath.sqrt(sum(x**2 for x in reduced[i]))
        print(f"  v{i}: {mpmath.log(length, 2)}")

    for row in reduced:
        potential_d_prime = abs(int(row[n])) 

        if potential_d_prime == 0 or potential_d_prime >= P: continue
        
        # d = 2^bits * d' + d_mod
        d = (potential_d_prime * mod + d_mod) % P
        if verify_key(d, address):
            print(f"!!! SUCCESS !!! Private key found for {address}")
            print(f"d = {hex(d)}")
            return d
            
        # Try negative
        d_neg = ((-potential_d_prime % P) * mod + d_mod) % P
        if verify_key(d_neg, address):
            print(f"!!! SUCCESS !!! Private key found for {address} (neg)")
            print(f"d = {hex(d_neg)}")
            return d_neg
            
    print("Failed to find d'.")
    return None

if __name__ == "__main__":
    solve_15Z5YJaa('sigs_15Z5YJaa_all.json', 51496, 16)
