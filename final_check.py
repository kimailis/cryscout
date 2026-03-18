import sqlite3
import pandas as pd
import datetime
import time

conn = sqlite3.connect('cryscout.db')

print(f"--- CRYSCOUT SYSTEM STATUS CHECK @ {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")

print("1. DATABASE METRICS:")
cursor = conn.cursor()
cursor.execute("SELECT COUNT(*) FROM addresses")
total_addrs = cursor.fetchone()[0]
cursor.execute("SELECT COUNT(*) FROM signatures")
total_sigs = cursor.fetchone()[0]
cursor.execute("SELECT COUNT(*) FROM addresses WHERE sigs_fetched = 1")
fetched_addrs = cursor.fetchone()[0]
cursor.execute("SELECT COUNT(*) FROM addresses WHERE vulnerability_score > 0")
scored_addrs = cursor.fetchone()[0]
cursor.execute("SELECT COUNT(*) FROM addresses WHERE sigs_scanned = 1")
struck_addrs = cursor.fetchone()[0]

print(f"  - Total Addresses Monitored: {total_addrs}")
print(f"  - Total Signatures Extracted: {total_sigs}")
print(f"  - Addresses w/ Fetched Sigs: {fetched_addrs}")
print(f"  - Addresses Scored (>0): {scored_addrs}")
print(f"  - Addresses Struck (Scanned): {struck_addrs}\n")

print("2. WORKER HEARTBEATS (Last 2 minutes):")
df_workers = pd.read_sql_query("SELECT worker_id, task, cpu_usage, ram_usage, last_heartbeat FROM worker_status WHERE last_heartbeat > datetime('now', '-120 seconds')", conn)
if df_workers.empty:
    print("  [!] WARNING: No recent worker heartbeats found in DB.")
else:
    print(df_workers.to_string(index=False))
print("")

print("3. RECENT STRIKER ACTIVITY (Top 5 Scanned Targets):")
df_recent_strikes = pd.read_sql_query("""
SELECT address, vulnerability_score, sigs_scanned, processing_by 
FROM addresses 
WHERE sigs_scanned = 1 AND processing_by IS NULL
ORDER BY vulnerability_score DESC LIMIT 5
""", conn)
print(df_recent_strikes.to_string(index=False))
print("")

print("4. ANY VULNERABILITIES FOUND?")
df_vulns = pd.read_sql_query("SELECT address, type, severity, found_at FROM vulnerabilities ORDER BY found_at DESC LIMIT 5", conn)
if df_vulns.empty:
    print("  - None found yet.")
else:
    print(df_vulns.to_string(index=False))

print("\n5. ANY KEYS RECOVERED?!")
df_keys = pd.read_sql_query("SELECT address, method, found_at FROM recovered_keys ORDER BY found_at DESC LIMIT 5", conn)
if df_keys.empty:
    print("  - No private keys recovered yet.")
else:
    print(df_keys.to_string(index=False))

conn.close()
