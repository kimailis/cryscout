import sqlite3

conn = sqlite3.connect('cryscout.db')
cursor = conn.cursor()

print("--- Tables ---")
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()
for table in tables:
    print(f"\nTable: {table[0]}")
    cursor.execute(f"PRAGMA table_info({table[0]})")
    for col in cursor.fetchall():
        print(f"  {col[1]} ({col[2]})")

conn.close()
