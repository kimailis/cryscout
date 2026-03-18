import sqlite3
import pandas as pd

conn = sqlite3.connect('cryscout.db')

print("=== CHECKING ALL HIGH VULNERABILITY TARGETS ===")
df = pd.read_sql_query("""
SELECT a.address, a.balance, a.vulnerability_score, a.sigs_scanned, a.processing_by 
FROM addresses a
WHERE a.vulnerability_score > 0
ORDER BY a.vulnerability_score DESC LIMIT 15
""", conn)
print(df)

conn.close()
