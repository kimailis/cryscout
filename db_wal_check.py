import sqlite3

conn = sqlite3.connect('cryscout.db')
cursor = conn.cursor()
cursor.execute("PRAGMA journal_mode;")
mode = cursor.fetchone()[0]
print(f"Current journal_mode: {mode}")

if mode.lower() != 'wal':
    cursor.execute("PRAGMA journal_mode=WAL;")
    mode_after = cursor.fetchone()[0]
    print(f"Changed journal_mode to: {mode_after}")
    
cursor.execute("PRAGMA synchronous=NORMAL;")
conn.commit()
conn.close()
