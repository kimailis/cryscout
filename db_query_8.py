import sqlite3
import pandas as pd

conn = sqlite3.connect('cryscout.db')

print("=== CHECKING COMPLETED STRIKES ===")
df = pd.read_sql_query("""
SELECT address, vulnerability_score, sigs_scanned, processing_by
FROM addresses
WHERE sigs_scanned = 1
ORDER BY vulnerability_score DESC LIMIT 15
""", conn)
print(df)

conn.close()
