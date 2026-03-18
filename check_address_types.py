import sqlite3

conn = sqlite3.connect('cryscout.db')
cursor = conn.cursor()

rows = cursor.execute('SELECT address FROM addresses WHERE balance >= 20').fetchall()
types = {'Legacy (1...)': 0, 'P2SH (3...)': 0, 'SegWit (bc1q...)': 0, 'Other': 0}

for r in rows:
    addr = r[0]
    if addr.startswith('1'):
        types['Legacy (1...)'] += 1
    elif addr.startswith('3'):
        types['P2SH (3...)'] += 1
    elif addr.startswith('bc1q'):
        types['SegWit (bc1q...)'] += 1
    else:
        types['Other'] += 1

print(types)
conn.close()
