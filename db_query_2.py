import sqlite3
import pandas as pd

conn = sqlite3.connect('cryscout.db')

print("=== CHECKING PROCESSING TARGETS ===")
df_proc = pd.read_sql_query("SELECT address, vulnerability_score, sigs_scanned, processing_by FROM addresses WHERE vulnerability_score > 0 ORDER BY vulnerability_score DESC LIMIT 10", conn)
print(df_proc)

conn.close()
