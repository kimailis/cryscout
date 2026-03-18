import sqlite3

conn = sqlite3.connect('cryscout.db')
cursor = conn.cursor()

tables = ['signatures', 'recovered_keys', 'vulnerabilities']
for t in tables:
    print(f"\nSchema for {t}:")
    res = cursor.execute(f"SELECT sql FROM sqlite_master WHERE name='{t}'").fetchone()
    if res:
        print(res[0])
    else:
        print("Table not found")

print("\n--- COUNT > 1000 BTC ---")
count = cursor.execute('SELECT COUNT(*) FROM addresses WHERE balance > 1000').fetchone()[0]
print(f"Total addresses with balance > 1000: {count}")

conn.close()
