import sqlite3

conn = sqlite3.connect('cryscout.db')
cursor = conn.cursor()

# Manually trigger the Striker query to see if it locks when executed by Python
query = """
SELECT a.address, a.balance, COUNT(s.id), MAX(s.pubkey_hex), a.vulnerability_score 
FROM addresses a JOIN signatures s ON a.address = s.address 
WHERE (a.sigs_scanned = 0 OR a.sigs_scanned IS NULL)
  AND (a.processing_by IS NULL OR a.processing_since < datetime('now', '-1 hour'))
  AND a.vulnerability_score > 0
GROUP BY a.address HAVING COUNT(s.id) >= 2 
ORDER BY a.rank ASC 
LIMIT 10
"""
cursor.execute(query)
results = cursor.fetchall()
print(f"Striker Query returned {len(results)} rows.")
for r in results:
    print(r)

conn.close()
