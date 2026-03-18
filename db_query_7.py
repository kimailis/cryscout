import sqlite3
import pandas as pd

conn = sqlite3.connect('cryscout.db')

print("=== CHECKING VULNERABILITIES FOUND ===")
df = pd.read_sql_query("""
SELECT address, type, severity, found_at, details
FROM vulnerabilities
ORDER BY found_at DESC LIMIT 10
""", conn)
print(df)

conn.close()
