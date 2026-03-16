import sqlite3
import hashlib
from ecdsa import SECP256k1

P = SECP256k1.order

def check_deterministic():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    cursor.execute('SELECT address, r_int, s_int, z_int FROM signatures WHERE r_int IS NOT NULL')
    rows = cursor.fetchall()
    conn.close()
    
    sigs = []
    for addr, r, s, z in rows:
        sigs.append({'addr': addr, 'r': int(r), 's': int(s), 'z': int(z)})
        
    print(f"Checking {len(sigs)} signatures for deterministic k = f(d)...")
    
    # 1. Try small d
    for d in range(1, 1000000):
        # Many old tools used k = SHA256(d) or similar
        k = int(hashlib.sha256(d.to_bytes(32, 'big')).hexdigest(), 16) % P
        
        # Check if this d, k pair works for ANY signature
        # s*k = z + r*d => z = s*k - r*d
        # We can pre-calculate some of this but let's just loop for now
        
        # To speed up, we only check for d once we have a candidate
        pass

    # Actually, more efficient:
    # for each signature:
    #   if k = f(d), then s*f(d) - r*d = z mod n
    # This is still hard to solve for d.
    
    # But we can brute force d and check!
    for d in range(1, 100000):
        k = int(hashlib.sha256(d.to_bytes(32, 'big')).hexdigest(), 16) % P
        for s in sigs:
            if (s['s'] * k) % P == (s['z'] + s['r'] * d) % P:
                print(f"!!! SUCCESS !!! Deterministic key found: {hex(d)}")
                return d
                
    print("Done.")

if __name__ == "__main__":
    check_deterministic()
