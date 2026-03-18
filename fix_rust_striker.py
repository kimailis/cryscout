import sqlite3

conn = sqlite3.connect('cryscout.db')
cursor = conn.cursor()

# Get the count of targets available for the striker
query = """
SELECT COUNT(DISTINCT a.address)
FROM addresses a JOIN signatures s ON a.address = s.address 
WHERE (a.sigs_scanned = 0 OR a.sigs_scanned IS NULL)
  AND (a.processing_by IS NULL OR a.processing_since < datetime('now', '-1 hour'))
  AND a.vulnerability_score > 0
"""
cursor.execute(query)
count = cursor.fetchone()[0]
print(f"Total targets currently available for Striker: {count}")

conn.close()
