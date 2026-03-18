import sqlite3

conn = sqlite3.connect('cryscout.db')
cursor = conn.cursor()

# Manually execute the exact logic the Rust striker uses to find targets to see why it fails
query = """
SELECT a.address, a.balance, COUNT(s.id), a.vulnerability_score 
FROM addresses a 
JOIN signatures s ON a.address = s.address 
WHERE (a.sigs_scanned = 0 OR a.sigs_scanned IS NULL)
  AND a.vulnerability_score > 0
GROUP BY a.address 
HAVING COUNT(s.id) >= 2 
"""
cursor.execute(query)
results = cursor.fetchall()
print(f"Eligible targets for Striker with >2 sigs: {len(results)}")
for r in results[:5]:
    print(r)

conn.close()
