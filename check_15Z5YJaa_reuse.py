import sqlite3

def check_reuse():
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    addr = '15Z5YJaaNSxeynvr6uW6jQZLwq3n1Hu6RX'
    
    # Get all signatures for this address
    cur.execute('SELECT r_int, s_int, z_int, txid FROM signatures WHERE address = ?', (addr,))
    rows = cur.fetchall()
    
    sigs_by_r = {}
    for r, s, z, txid in rows:
        if r not in sigs_by_r: sigs_by_r[r] = []
        sigs_by_r[r].append({'s': int(s), 'z': int(z), 'txid': txid})
    
    vulnerable = False
    for r, sigs in sigs_by_r.items():
        if len(sigs) > 1:
            # Check if there are different Z values or different S values for the same R
            # Actually if R is same and Z is same and S is same, it's just a duplicate.
            # If R is same and Z is different, it's solvable.
            # If R is same and S is different but Z is same, it means k is same but the 
            # signature was generated differently or it's a mutation (unlikely in Bitcoin unless S/P-S).
            
            z_values = set(sig['z'] for sig in sigs)
            if len(z_values) > 1:
                print(f"!!! VULNERABLE R-REUSE FOUND for {addr} (r={r}) !!!")
                vulnerable = True
                # Solvable: d = (s1*z2 - s2*z1) / (r*(s2-s1))
                # Or k = (z1-z2)/(s1-s2)
                # d = (s1*k - z1)/r
                P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
                s1 = sigs[0]['s']
                z1 = sigs[0]['z']
                s2 = sigs[1]['s']
                z2 = sigs[1]['z']
                r_int = int(r)
                
                k = ((z1 - z2) * pow(s1 - s2, -1, P)) % P
                d = ((s1 * k - z1) * pow(r_int, -1, P)) % P
                print(f"Recovered Private Key: {hex(d)}")
                
    if not vulnerable:
        print(f"No solvable R-reuse found for {addr}. All reuses have identical Z values.")
    
    conn.close()

if __name__ == '__main__':
    check_reuse()
