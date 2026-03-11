import sqlite3
import json

conn = sqlite3.connect('cryscout.db')
c = conn.cursor()
c.execute("SELECT address, fail_att, status FROM addresses WHERE status != 'Compromised' LIMIT 20")
rows = c.fetchall()
print(f"{'Address':<35} | {'Status':<15} | {'Fail Att'}")
print("-" * 70)
for row in rows:
    print(f"{row[0][:35]:<35} | {row[2]:<15} | {row[1]}")

c.execute("SELECT COUNT(*) FROM addresses WHERE fail_att GLOB '*[1.[3-9]]*' AND fail_att GLOB '*[2.[3-9]]*' AND fail_att GLOB '*[3.[3-9]]*' AND fail_att GLOB '*[4.[3-9]]*' AND fail_att GLOB '*[5.[3-9]]*' AND fail_att GLOB '*[6.[3-9]]*' AND fail_att GLOB '*[7.[3-9]]*'")
count = c.fetchone()[0]
print(f"\nAddresses ready for BRUTEFORCE: {count}")
conn.close()
