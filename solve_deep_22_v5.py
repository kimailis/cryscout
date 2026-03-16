import collections
import json
import mpmath
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key

P = SECP256k1.order
mpmath.mp.prec = 1024

def fast_lll(basis, delta=0.99):
    n = len(basis)
    m = len(basis[0])
    basis = [[mpmath.mpf(x) for x in row] for row in basis]
    B_star = [[mpmath.mpf(0)] * m for _ in range(n)]
    mu = [[mpmath.mpf(0)] * n for _ in range(n)]
    d = [mpmath.mpf(0)] * n
    for i in range(n):
        B_star[i] = list(basis[i])
        for j in range(i):
            num = sum(basis[i][k] * B_star[j][k] for k in range(m))
            mu[i][j] = num / d[j] if d[j] != 0 else mpmath.mpf(0)
            for k in range(m):
                B_star[i][k] -= mu[i][j] * B_star[j][k]
        d[i] = sum(x*x for x in B_star[i])
    k = 1
    while k < n:
        for j in range(k-1, -1, -1):
            if abs(mu[k][j]) > 0.5:
                q = round(mu[k][j])
                for l in range(m):
                    basis[k][l] -= q * basis[j][l]
                for idx in range(j):
                    mu[k][idx] -= q * mu[j][idx]
                mu[k][j] -= q
        if d[k] >= (delta - mu[k][k-1]**2) * d[k-1]:
            k += 1
        else:
            basis[k], basis[k-1] = basis[k-1], basis[k]
            mu_k_km1 = mu[k][k-1]
            B_star_k_new = [B_star[k][l] + mu_k_km1 * B_star[k-1][l] for l in range(m)]
            d_k_new = sum(x*x for x in B_star_k_new)
            mu_new = mu_k_km1 * d[k-1] / d_k_new if d_k_new != 0 else mpmath.mpf(0)
            B_star_km1_new = [B_star[k-1][l] - mu_new * B_star_k_new[l] for l in range(m)]
            d_km1_new = sum(x*x for x in B_star_km1_new)
            c_star_norm = d[k]
            for i in range(k+1, n):
                mu_i_km1 = mu[i][k-1]
                mu_i_k = mu[i][k]
                mu[i][k-1] = mu_i_km1 * mu_new + mu_i_k * (c_star_norm / d_k_new if d_k_new != 0 else 0)
                mu[i][k] = mu_i_km1 - mu_k_km1 * mu_i_k
            for j in range(k-1):
                mu[k-1][j], mu[k][j] = mu[k][j], mu[k-1][j]
            mu[k][k-1] = mu_new
            B_star[k-1] = B_star_k_new
            B_star[k] = B_star_km1_new
            d[k-1] = d_k_new
            d[k] = d_km1_new
            k = max(k-1, 1)
    return basis

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
        prepared.append({'u': u, 't': t, 'a_k': a_k, 'r': s['r'], 's': s['s']})
    counts = collections.Counter([p['a_k'] for p in prepared])
    top_a_ks = [ak for ak, count in counts.most_common(5)]
    print(f"Top a_ks: {top_a_ks}")
    best_sigs = [p for p in prepared if p['a_k'] in top_a_ks]
    print(f"Using {len(best_sigs)} sigs from top 5 groups.")
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
    print("Starting LLL...")
    reduced = fast_lll(matrix)
    print("Checking results...")
    for row in reduced:
        d_prime = abs(int(row[n]))
        for dp in [d_prime, (P - d_prime) % P]:
            if dp == 0: continue
            d = (dp * mod + d_mod) % P
            if verify_key(d, address):
                print(f"!!! SUCCESS !!! Private key: {hex(d)}")
                return d
    print("Failed.")

if __name__ == "__main__":
    solve()
