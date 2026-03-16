import sqlite3
import collections
import json

def investigate():
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    address = "1FdPpELnjHfwSM4Nvi7LdYS4S4GVGsLUQY"
    cur.execute('SELECT r_int, s_int, z_int, txid FROM signatures WHERE address = ?', (address,))
    rows = cur.fetchall()
    
    bits = 20
    d_mod = 911798
    mod = 1 << bits
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    sigs = []
    for r, s, z, txid in rows:
        r, s, z = int(r), int(s), int(z)
        s_inv = pow(s, -1, P)
        a_k = ((z + r * d_mod) * s_inv) % mod
        sigs.append({'a_k': a_k, 'r': r, 's': s, 'z': z, 'txid': txid})
    
    counts = collections.Counter([s['a_k'] for s in sigs])
    groups = []
    for val, count in counts.items():
        if count >= 3:
            group_sigs = [s for s in sigs if s['a_k'] == val]
            groups.append({'a_k': val, 'sigs': group_sigs})
            print(f"Group a_k={val} has {count} sigs.")
    
    # Check for larger bias in these groups
    for group in groups:
        a_k = group['a_k']
        group_sigs = group['sigs']
        
        # Test more bits
        for b in range(21, 256):
            m = 1 << b
            # dt * d = du (mod m)
            # Since we only have a few sigs, we check if they share d % m
            d_mods = []
            for i in range(len(group_sigs)):
                for j in range(i + 1, len(group_sigs)):
                    ti = (pow(group_sigs[i]['s'], -1, P) * group_sigs[i]['r']) % P
                    tj = (pow(group_sigs[j]['s'], -1, P) * group_sigs[j]['r']) % P
                    ui = (pow(group_sigs[i]['s'], -1, P) * group_sigs[i]['z']) % P
                    uj = (pow(group_sigs[j]['s'], -1, P) * group_sigs[j]['z']) % P
                    
                    dt = (ti - tj) % m
                    du = (uj - ui) % m
                    if dt % 2 != 0:
                        try:
                            dm = (du * pow(dt, -1, m)) % m
                            d_mods.append(dm)
                        except: pass
            
            if d_mods and all(dm == d_mods[0] for dm in d_mods):
                print(f"  !!! Potential higher bias found for group {a_k}: {b} bits, d_mod={d_mods[0]}")
            else:
                # If they don't agree anymore, then the bias was only up to b-1
                if b > 21:
                    print(f"  Bias for group {a_k} seems to be {b-1} bits.")
                break

if __name__ == "__main__":
    investigate()
