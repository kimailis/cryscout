import sqlite3
import pandas as pd

conn = sqlite3.connect('cryscout.db')

print("=== CHECKING SIGNATURES FOR TOP TARGET ===")
df_sigs = pd.read_sql_query("SELECT COUNT(*) as sig_count FROM signatures WHERE address = '1GSrCrtjZ6nk3Yn2wuY2qyXo8qPLGgAMqQ'", conn)
print(df_sigs)

conn.close()
