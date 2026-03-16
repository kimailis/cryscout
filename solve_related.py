import sqlite3
import collections
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key

P = SECP256k1.order

def solve():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    cursor.execute('SELECT address FROM signatures GROUP BY address HAVING count(*) >= 2')
    addrs = [row[0] for row in cursor.fetchall()]
    
    print(f"Checking {len(addrs)} addresses for related nonces...")
    
    for addr in addrs:
        cursor.execute('SELECT r_int, s_int, z_int FROM signatures WHERE address = ?', (addr,))
        rows = cursor.fetchall()
        
        sigs = []
        for r, s, z in rows:
            if r is None or s is None or z is None: continue
            try:
                sigs.append({
                    'u': (pow(int(s), -1, P) * int(z)) % P,
                    't': (pow(int(s), -1, P) * int(r)) % P
                })
            except: continue
            
        n = len(sigs)
        if n < 2: continue
        
        # d = (du - delta) / dt
        for i in range(min(n, 100)):
            for j in range(i + 1, min(n, 100)):
                du = (sigs[i]['u'] - sigs[j]['u']) % P
                dt = (sigs[j]['t'] - sigs[i]['t']) % P
                if dt == 0: continue
                dt_inv = pow(dt, -1, P)
                
                # Check delta from -100 to 100
                for delta in range(-100, 101):
                    if delta == 0: continue
                    d = ((du - delta) * dt_inv) % P
                    
                    if verify_key(d, addr):
                        print(f"!!! SUCCESS !!! Related Nonce Found!")
                        print(f"Address: {addr}")
                        print(f"Key: {hex(d)}")
                        print(f"Delta: {delta}")
                        return d
    print("Done checking.")
    conn.close()

if __name__ == "__main__":
    solve()
