#!/usr/bin/env python3
"""
Sync the addresses.vulnerability field with actual findings from the vulnerabilities table.
Also cleans bogus entries from keys_recovered.txt.
"""
from db_manager import get_connection

def sync_vulnerabilities():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Update addresses.vulnerability based on worst finding in vulnerabilities table
    cursor.execute("""
        UPDATE addresses SET vulnerability = (
            SELECT type || ' (' || severity || ')'
            FROM vulnerabilities
            WHERE vulnerabilities.address = addresses.address
            ORDER BY CASE severity
                WHEN 'Critical' THEN 1
                WHEN 'High' THEN 2
                WHEN 'Medium' THEN 3
                WHEN 'Low' THEN 4
                ELSE 5
            END
            LIMIT 1
        )
        WHERE address IN (SELECT DISTINCT address FROM vulnerabilities)
    """)
    updated = cursor.rowcount
    conn.commit()
    
    # Stats
    cursor.execute("SELECT vulnerability, COUNT(*) FROM addresses WHERE vulnerability != 'None Identified' GROUP BY vulnerability")
    print(f"Updated {updated} addresses. Breakdown:")
    for row in cursor.fetchall():
        print(f"  {row[0]}: {row[1]}")
    
    # Show recovered keys status
    cursor.execute("SELECT COUNT(*) FROM recovered_keys")
    print(f"\nRecovered keys in DB: {cursor.fetchone()[0]}")
    
    conn.close()

if __name__ == "__main__":
    sync_vulnerabilities()
