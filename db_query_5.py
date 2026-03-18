import sqlite3
import pandas as pd

conn = sqlite3.connect('cryscout.db')

print("=== CHECKING ALL TARGETS ELIGIBLE FOR STRIKE ===")
df = pd.read_sql_query("""
SELECT a.address, a.balance, COUNT(s.id) as sig_count, a.vulnerability_score, a.sigs_scanned, a.processing_by 
FROM addresses a LEFT JOIN signatures s ON a.address = s.address 
WHERE a.vulnerability_score > 0 AND (a.sigs_scanned = 0 OR a.sigs_scanned IS NULL)
GROUP BY a.address
ORDER BY a.vulnerability_score DESC LIMIT 15
""", conn)
print(df)

conn.close()
