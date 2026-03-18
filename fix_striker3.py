import sqlite3

conn = sqlite3.connect('cryscout.db')
cursor = conn.cursor()

# Get a target to strike
query = """
SELECT a.address, a.balance, COUNT(s.id), MAX(s.pubkey_hex), a.vulnerability_score 
FROM addresses a JOIN signatures s ON a.address = s.address 
WHERE (a.sigs_scanned = 0 OR a.sigs_scanned IS NULL)
  AND (a.processing_by IS NULL OR a.processing_since < datetime('now', '-1 hour'))
  AND a.vulnerability_score > 0
GROUP BY a.address HAVING COUNT(s.id) >= 2 
ORDER BY a.rank ASC 
LIMIT 1
"""
cursor.execute(query)
target = cursor.fetchone()
if target:
    print(f"Executing manual strike on {target[0]}...")
    
    # mark it as processing
    cursor.execute("UPDATE addresses SET processing_by = 'manual', processing_since = datetime('now') WHERE address = ?", (target[0],))
    conn.commit()
    print("Locked target successfully.")
else:
    print("No targets available for striking.")

conn.close()
