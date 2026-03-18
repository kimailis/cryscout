import sqlite3

conn = sqlite3.connect('cryscout.db')
cursor = conn.cursor()

# Reset sigs_scanned for high vulnerability targets so the striker can process them
cursor.execute("""
UPDATE addresses 
SET sigs_scanned = 0, processing_by = NULL 
WHERE vulnerability_score > 1.5;
""")
print(f"Rows updated: {cursor.rowcount}")

conn.commit()
conn.close()
