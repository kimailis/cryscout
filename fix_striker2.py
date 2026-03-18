import sqlite3

conn = sqlite3.connect('cryscout.db')
cursor = conn.cursor()

# Manually execute the EXACT logic the Rust striker uses, including the processing_by check
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
print(f"Eligible targets with processing_by check: {len(results)}")
for r in results[:5]:
    print(r)

# Check what the processing_by column looks like for the eligible targets
cursor.execute("""
SELECT a.address, a.processing_by, a.processing_since
FROM addresses a 
JOIN signatures s ON a.address = s.address 
WHERE (a.sigs_scanned = 0 OR a.sigs_scanned IS NULL)
  AND a.vulnerability_score > 0
GROUP BY a.address 
HAVING COUNT(s.id) >= 2 
LIMIT 5
""")
print("\nProcessing status of potential targets:")
for r in cursor.fetchall():
    print(r)

conn.close()
