import sqlite3
import os

DB_NAME = 'cryscout.db'

def check_recent():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Check column names in addresses table
    cursor.execute("PRAGMA table_info(addresses)")
    columns = [col[1] for col in cursor.fetchall()]
    print(f"Columns: {columns}")
    
    cursor.execute("SELECT address, status, type, first_seen, last_updated FROM addresses ORDER BY last_updated DESC LIMIT 20")
    rows = cursor.fetchall()
    
    print("\nRecently added/updated addresses:")
    for row in rows:
        print(row)
    
    conn.close()

if __name__ == "__main__":
    check_recent()
