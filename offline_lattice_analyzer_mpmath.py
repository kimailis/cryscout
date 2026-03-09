import json
import sys
import hashlib
import base58
import mpmath
from ecdsa import SigningKey, SECP256k1

# SECP256K1 Curve Order
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Set precision to handle 256-bit numbers
mpmath.mp.prec = 512

def verify_key(d, address):
    try:
        import hashlib, base58
        d_bytes = int(d).to_bytes(32, 'big')
        sk = SigningKey.from_secret_string(d_bytes, curve=SECP256k1)
        vk = sk.verifying_key
        pubkey_uncomp = b'\x04' + vk.to_string()
        sha256 = hashlib.sha256(pubkey_uncomp).digest()
        ripemd160 = hashlib.new('ripemd160', sha256).digest()
        vh = b'\x00' + ripemd160
        checksum = hashlib.sha256(hashlib.sha256(vh).digest()).digest()[:4]
        addr = base58.b58encode(vh + checksum).decode()
        return addr == address
    except: return False

def lll_reduction_mp(basis):
    n = len(basis)
    m = len(basis[0])
    mu = [[mpmath.mpf(0) for _ in range(n)] for _ in range(n)]
    b_star = [[mpmath.mpf(0) for _ in range(m)] for _ in range(n)]
    d = [mpmath.mpf(0)] * n

    def update_orthogonalization(i):
        b_star[i] = [mpmath.mpf(x) for x in basis[i]]
        for j in range(i):
            num = sum(b_star[i][k] * b_star[j][k] for k in range(m))
            mu[i][j] = num / d[j] if d[j] != 0 else mpmath.mpf(0)
            for k in range(m):
                b_star[i][k] -= mu[i][j] * b_star[j][k]
        d[i] = sum(x**2 for x in b_star[i])

    for i in range(n):
        update_orthogonalization(i)

    k = 1
    while k < n:
        for j in range(k-1, -1, -1):
            if abs(mu[k][j]) > 0.5:
                q = round(mu[k][j])
                for l in range(m):
                    basis[k][l] -= q * basis[j][l]
                update_orthogonalization(k)
        
        if d[k] >= (0.75 - mu[k][k-1]**2) * d[k-1]:
            k += 1
        else:
            basis[k], basis[k-1] = basis[k-1], basis[k]
            update_orthogonalization(k-1)
            update_orthogonalization(k)
            k = max(k-1, 1)
    return basis

def solve_hnp_mp(sigs_data, bias_bits, address=None):
    n = len(sigs_data)
    if n < 2: return None
    B = 2**(256 - bias_bits) 
    matrix = [[0] * (n + 2) for _ in range(n + 2)]
    t_values = []
    u_values = []
    for sig in sigs_data:
        s_inv = pow(sig['s'], -1, P)
        t = (s_inv * sig['r']) % P
        u = (s_inv * sig['z']) % P
        t_values.append(t)
        u_values.append(u)
    for i in range(n): matrix[i][i] = P
    for i in range(n): matrix[n][i] = t_values[i]
    matrix[n][n] = 1 
    for i in range(n): matrix[n+1][i] = u_values[i]
    matrix[n+1][n+1] = B
    
    reduced = lll_reduction_mp(matrix)
    for row in reduced:
        potential_d = abs(row[n]) 
        if potential_d == 0 or potential_d >= P: continue
        if address:
            if verify_key(potential_d, address): return potential_d
    return None

def offline_lattice(filename, address):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    print(f"Loaded {len(sigs)} sigs from {filename}")
    
    # Check for small bias with all signatures
    for b in [8, 12, 16]:
        print(f"Trying bias_bits={b} with {len(sigs)} sigs...")
        key = solve_hnp_mp(sigs, b, address=address)
        if key:
            print(f"!!! SUCCESS at bias_bits={b} !!!")
            print(f"Private Key: {hex(key)}")
            return key
    print("No key found.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 offline_lattice_analyzer_mpmath.py <json_file> <address>")
    else:
        offline_lattice(sys.argv[1], sys.argv[2])
