import sqlite3
from ecdsa import SECP256k1

def check_custom_bias():
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    P = SECP256k1.order
    
    cur.execute('SELECT r_hex, s_hex, z_hex, address FROM signatures')
    rows = cur.fetchall()
    
    for r_hex, s_hex, z_hex, addr in rows:
        r, s, z = int(r_hex, 16), int(s_hex, 16), int(z_hex, 16)
        
        # k = (z + r*d) / s
        # Try k = small * z
        # small * z * s = z + r*d => d = (small * z * s - z) / r
        for small in range(1, 100):
            d = ((small * z * s - z) * pow(r, -1, P)) % P
            # We would need to verify d, but let's just see if any are very small
            if d < 10**12:
                print(f"Possible small D for {addr}: {hex(d)} (k = {small}*z)")
                
        # Try k = z + small
        # (z + small) * s = z + r*d => d = ((z + small) * s - z) / r
        for small in range(1, 100):
            d = (((z + small) * s - z) * pow(r, -1, P)) % P
            if d < 10**12:
                print(f"Possible small D for {addr}: {hex(d)} (k = z + {small})")

if __name__ == "__main__":
    check_custom_bias()
