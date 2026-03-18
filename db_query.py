import sqlite3
import pandas as pd

conn = sqlite3.connect('cryscout.db')

print("=== RECOVERED KEYS ===")
df_keys = pd.read_sql_query("SELECT address, method, found_at FROM recovered_keys LIMIT 10", conn)
print(df_keys)

print("\n=== TOP VULNERABLE TARGETS ===")
df_vuln = pd.read_sql_query("SELECT address, vulnerability_score, potential_weakness, rank FROM addresses WHERE vulnerability_score > 0 ORDER BY vulnerability_score DESC LIMIT 5", conn)
print(df_vuln)

print("\n=== RECENT VULNERABILITIES ===")
df_v = pd.read_sql_query("SELECT address, type, severity, found_at FROM vulnerabilities ORDER BY found_at DESC LIMIT 5", conn)
print(df_v)

conn.close()
