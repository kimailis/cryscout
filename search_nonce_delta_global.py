import sqlite3
import collections
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key

P = SECP256k1.order

def solve():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    # Sample many signatures from different addresses
    cursor.execute('SELECT address, r_int, s_int, z_int FROM signatures WHERE r_int IS NOT NULL LIMIT 1000')
    rows = cursor.fetchall()
    
    sigs = []
    for addr, r, s, z in rows:
        try:
            sigs.append({
                'addr': addr,
                'u': (pow(int(s), -1, P) * int(z)) % P,
                't': (pow(int(s), -1, P) * int(r)) % P
            })
        except: continue
        
    n = len(sigs)
    print(f"Checking cross-address relations for {n} signatures...")
    
    # We look for k1 - k2 = delta
    # (u1 + t1*d1) - (u2 + t2*d2) = delta
    # This only works if d1 = d2 (same key, different address)
    # OR if we can eliminate d.
    
    # But wait! If nonces are related across addresses, it's often k1 = k2.
    # We already checked R-reuse (k1 = k2 => r1 = r2).
    
    # What if k1 = SHA256(something) and k2 = SHA256(something + 1)?
    # This would imply a delta.
    
    # Let's check if any (u_i - delta) / t_i is the same for different addresses
    # This is still assuming same d.
    
    # Let's try another approach: check for nonces that are very SMALL.
    # We already checked r_bits < 160.
    
    # How about k = SHA256(private_key)? (Weak deterministic nonce)
    # Many old tools did this before RFC 6979.
    # s*k = z + r*d => s*SHA256(d) = z + r*d
    # This is a non-linear equation in d.
    
    pass

if __name__ == "__main__":
    solve()
