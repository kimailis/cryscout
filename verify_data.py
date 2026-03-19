import sqlite3
import pandas as pd

conn = sqlite3.connect('cryscout.db')

print("=== LATEST SIGNATURES ===")
query = """
SELECT address, txid, vin, r_hex, s_hex, z_hex, timestamp 
FROM signatures 
ORDER BY id DESC 
LIMIT 5
"""
df_sigs = pd.read_sql_query(query, conn)
for i, row in df_sigs.iterrows():
    print(f"Index: {i}")
    print(f"  Address:   {row['address']}")
    print(f"  TXID:      {row['txid']}")
    print(f"  VIN:       {row['vin']}")
    print(f"  R (hex):   {row['r_hex'][:16]}...")
    print(f"  S (hex):   {row['s_hex'][:16]}...")
    print(f"  Z (hex):   {row['z_hex'][:16]}...")
    print(f"  Timestamp: {row['timestamp']}")
    print("-" * 40)

print("\n=== LATEST VULNERABILITIES ===")
query_v = "SELECT address, type, severity, details, found_at FROM vulnerabilities ORDER BY found_at DESC LIMIT 5"
df_v = pd.read_sql_query(query_v, conn)
print(df_v)

conn.close()
