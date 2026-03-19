import sqlite3
import pandas as pd

conn = sqlite3.connect('cryscout.db')

print("=== WORKER STATUS ===")
print(pd.read_sql_query("SELECT * FROM worker_status", conn))

print("\n=== GLOBAL STATS ===")
print(pd.read_sql_query("SELECT * FROM global_stats", conn))

print("\n=== RECENT VULNERABILITIES (Detailed) ===")
print(pd.read_sql_query("SELECT address, type, details, severity, found_at FROM vulnerabilities ORDER BY found_at DESC LIMIT 10", conn))

print("\n=== DATABASE COUNTS ===")
print(f"Addresses: {conn.execute('SELECT count(*) FROM addresses').fetchone()[0]}")
print(f"Signatures: {conn.execute('SELECT count(*) FROM signatures').fetchone()[0]}")
print(f"Vulnerabilities: {conn.execute('SELECT count(*) FROM vulnerabilities').fetchone()[0]}")
print(f"Recovered Keys: {conn.execute('SELECT count(*) FROM recovered_keys').fetchone()[0]}")

conn.close()
