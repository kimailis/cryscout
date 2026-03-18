import sqlite3

conn = sqlite3.connect('cryscout.db')
cursor = conn.cursor()
sigs = cursor.execute('SELECT r_hex, s_hex, z_hex, txid FROM signatures WHERE address = "1FmLMbBLwJrnm3giK69WtKrH9yQZqecDjD"').fetchall()

print(f"Total signatures: {len(sigs)}")

for i in range(len(sigs)):
    for j in range(i + 1, len(sigs)):
        r1, s1, z1, tx1 = sigs[i]
        r2, s2, z2, tx2 = sigs[j]
        
        # Strip and normalize leading zeros for comparison
        r1_norm = r1.strip().lstrip('0')
        r2_norm = r2.strip().lstrip('0')
        s1_norm = s1.strip().lstrip('0')
        s2_norm = s2.strip().lstrip('0')
        z1_norm = z1.strip().lstrip('0')
        z2_norm = z2.strip().lstrip('0')

        # Real Reuse: Same R, different S, AND DIFFERENT TXIDs
        if r1_norm == r2_norm and s1_norm != s2_norm and tx1 != tx2:
            print("!!! AUTHENTIC REUSE FOUND !!!")
            print(f"R: {r1_norm}")
            print(f"S1: {s1_norm} (TX: {tx1})")
            print(f"S2: {s2_norm} (TX: {tx2})")
            print(f"Z1: {z1_norm}")
            print(f"Z2: {z2_norm}")

conn.close()
