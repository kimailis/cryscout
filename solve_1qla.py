import sqlite3
import collections
import mpmath
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key
from fast_lll import fast_lll

P = SECP256k1.order
mpmath.mp.prec = 512

def solve_for_dm(address, dm, k_mod, bits):
    print(f"\nTrying d mod {1<<bits} = {dm} | k mod {1<<bits} = {k_mod}")
    
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    cur.execute('SELECT r_int, s_int, z_int FROM signatures WHERE address LIKE ?', (address[:15] + '%',))
    rows = cur.fetchall()
    conn.close()
    
    mod = 1 << bits
    prepared = []
    for r, s, z in rows:
        r, s, z = int(r), int(s), int(z)
        s_inv = pow(s, -1, P)
        u = (s_inv * z) % P
        t = (s_inv * r) % P
        if (u + t * dm) % mod == k_mod:
            prepared.append({'u': u, 't': t})
            
    n = len(prepared)
    print(f"  Found {n} signatures matching bias.")
    if n < 40: # Too few for this bits
        return None

    # Limit to 100 for speed of fast_lll
    if n > 100:
        prepared = prepared[:100]
        n = 100

    B = 1 << (256 - bits)
    inv_mod = pow(mod, -1, P)
    
    matrix = [[0] * (n + 2) for _ in range(n + 2)]
    for i in range(n):
        u_p = ((prepared[i]['u'] + prepared[i]['t'] * dm - k_mod) * inv_mod) % P
        t_p = prepared[i]['t']
        matrix[i][i] = P
        matrix[n][i] = t_p
        matrix[n+1][i] = u_p
        
    matrix[n][n] = 1
    matrix[n+1][n+1] = B
    
    print(f"  Running LLL on {n+2}x{n+2} matrix...")
    reduced = fast_lll(matrix)
    
    for row in reduced:
        d_prime = abs(int(row[n]))
        for dp in [d_prime, (P - d_prime) % P]:
            if dp == 0: continue
            d = (dp * mod + dm) % P
            if verify_key(d, address):
                print(f"!!! SUCCESS !!! Private key: {hex(d)}")
                return d
    return None

if __name__ == "__main__":
    addr = "1QLASnDp9M2WShc"
    # We saw strong k mod 4 = 0 for d mod 4 = 0, 1, 2, 3
    # Let's try them all
    import sqlite3
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    cur.execute("SELECT address FROM signatures WHERE address LIKE ? LIMIT 1", (addr + '%',))
    full_addr = cur.fetchone()[0]
    conn.close()
    
    for dm in [0, 1, 2, 3]:
        if solve_for_dm(full_addr, dm, 0, 2):
            break
