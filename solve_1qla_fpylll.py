import sqlite3
import collections
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key
from fpylll import IntegerMatrix, LLL, BKZ

P = SECP256k1.order

def solve_for_dm(address, dm, k_mod, bits):
    print(f"\nTrying d mod {1<<bits} = {dm} | k mod {1<<bits} = {k_mod}")
    
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    cur.execute('SELECT r_int, s_int, z_int FROM signatures WHERE address LIKE ?', (address[:15] + '%',))
    rows = cur.fetchall()
    conn.close()
    
    mod = 1 << bits
    prepared = []
    seen = set()
    for r, s, z in rows:
        if (r, s) in seen: continue
        seen.add((r, s))
        r, s, z = int(r), int(s), int(z)
        s_inv = pow(s, -1, P)
        u = (s_inv * z) % P
        t = (s_inv * r) % P
        if (u + t * dm) % mod == k_mod:
            prepared.append({'u': u, 't': t})
            
    n = len(prepared)
    print(f"  Found {n} unique signatures matching bias.")
    if n < 40: # Too few for this bits
        return None

    B = 1 << (256 - bits)
    inv_mod = pow(mod, -1, P)
    
    mat = IntegerMatrix(n + 2, n + 2)
    for i in range(n):
        u_p = ((prepared[i]['u'] + prepared[i]['t'] * dm - k_mod) * inv_mod) % P
        t_p = prepared[i]['t']
        mat[i, i] = P
        mat[n, i] = t_p
        mat[n+1, i] = u_p
        
    mat[n, n] = 1
    mat[n+1, n+1] = B
    
    print(f"  Running fpylll LLL on {n+2}x{n+2} matrix...")
    LLL.reduction(mat)
    
    for i in range(mat.nrows):
        d_prime = abs(int(mat[i, n]))
        if d_prime == 0: continue
        for dp in [d_prime, (P - d_prime) % P]:
            d = (dp * mod + dm) % P
            if verify_key(d, address):
                print(f"!!! SUCCESS !!! Private key: {hex(d)}")
                return d
                
    print("  LLL failed, running BKZ-20...")
    BKZ.reduction(mat, BKZ.Param(block_size=20))
    for i in range(mat.nrows):
        d_prime = abs(int(mat[i, n]))
        if d_prime == 0: continue
        for dp in [d_prime, (P - d_prime) % P]:
            d = (dp * mod + dm) % P
            if verify_key(d, address):
                print(f"!!! SUCCESS !!! Private key: {hex(d)}")
                return d
    return None

if __name__ == "__main__":
    addr = "1QLASnDp9M2WShc"
    import sqlite3
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    cur.execute("SELECT address FROM signatures WHERE address LIKE ? LIMIT 1", (addr + '%',))
    row = cur.fetchone()
    conn.close()
    if row:
        full_addr = row[0]
        # We saw strong k mod 4 = 0 for d mod 4 = 0, 1, 2, 3
        for dm in [0, 1, 2, 3]:
            if solve_for_dm(full_addr, dm, 0, 2):
                break
