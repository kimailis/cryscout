import sqlite3
import json
from collections import Counter

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def get_sigs_from_db(address):
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    cur.execute('SELECT r_hex, s_hex, z_hex, txid FROM signatures WHERE address = ?', (address,))
    rows = cur.fetchall()
    sigs = []
    for r_hex, s_hex, z_hex, txid in rows:
        sigs.append({
            'r': int(r_hex, 16),
            's': int(s_hex, 16),
            'z': int(z_hex, 16),
            'txid': txid
        })
    conn.close()
    return sigs

def find_lsb_bias_address(address):
    sigs = get_sigs_from_db(address)
    n = len(sigs)
    if n == 0:
        print(f"No signatures found for {address}")
        return
    
    print(f"Deep checking for LSB bias in {n} sigs for {address}...")
    
    for b in range(1, 13): # Check up to 12 bits for speed
        mod = 1 << b
        for k_fixed in range(mod):
            d_candidates = []
            for i in range(n):
                r1 = sigs[i]['r']
                s1_val = sigs[i]['s']
                z1 = sigs[i]['z']
                
                rhs = (s1_val * k_fixed - z1) % mod
                if r1 % 2 != 0:
                    try:
                        d_mod = (rhs * pow(r1, -1, mod)) % mod
                        d_candidates.append(d_mod)
                    except ValueError: pass
            
            if not d_candidates: continue
            
            counts = Counter(d_candidates)
            best_d_mod, count = counts.most_common(1)[0]
            if count >= n * 0.9 and n > 5:
                print(f"!!! BIAS FOUND for {address} !!!")
                print(f"Bits: {b} | k_fixed: {k_fixed} | Possible d mod {mod} = {best_d_mod} ({count}/{n} sigs)")
                return b, k_fixed, best_d_mod
    return None

if __name__ == "__main__":
    import sys
    addresses = [
        '1FdPpELnjHfwSM4Nvi7LdYS4S4GVGsLUQY',
        '152kzDqjAVuPBMmJqcWvFbB7qkvigFXSLh',
        '1AV4KGCsvtPZ9tG7hvwgb85wJyFd9xdpFv',
        '13kxWCuDWN1gGSe2vPmsSBVXyPfYLMh6M4',
        '1HDNfSr5ExyGfe77GX681PPZtN2deoewfd',
        '15Z5YJaaNSxeynvr6uW6jQZLwq3n1Hu6RX'
    ]
    for addr in addresses:
        find_lsb_bias_address(addr)
