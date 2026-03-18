import sqlite3

conn = sqlite3.connect('cryscout.db')
cursor = conn.cursor()

# Get list of addresses to remove
high_balance_addresses = [row[0] for row in cursor.execute('SELECT address FROM addresses WHERE balance > 1000').fetchall()]

print(f"Removing {len(high_balance_addresses)} addresses with balance > 1000 BTC and their associated data...")

if high_balance_addresses:
    # Use chunks to avoid too long SQL statements if needed, but 527 is small enough for IN clause usually.
    # We'll do it in one go for each table.
    
    # 1. Delete from vulnerabilities
    cursor.execute('DELETE FROM vulnerabilities WHERE address IN (SELECT address FROM addresses WHERE balance > 1000)')
    v_count = cursor.rowcount
    print(f"Deleted {v_count} entries from vulnerabilities.")

    # 2. Delete from signatures
    cursor.execute('DELETE FROM signatures WHERE address IN (SELECT address FROM addresses WHERE balance > 1000)')
    s_count = cursor.rowcount
    print(f"Deleted {s_count} entries from signatures.")

    # 3. Delete from recovered_keys
    cursor.execute('DELETE FROM recovered_keys WHERE address IN (SELECT address FROM addresses WHERE balance > 1000)')
    rk_count = cursor.rowcount
    print(f"Deleted {rk_count} entries from recovered_keys.")

    # 4. Delete from addresses
    cursor.execute('DELETE FROM addresses WHERE balance > 1000')
    a_count = cursor.rowcount
    print(f"Deleted {a_count} entries from addresses.")

    conn.commit()
    print("Cleanup committed successfully.")
    
    # Vacuum to reclaim space
    print("Vacuuming database...")
    conn.execute('VACUUM')
    print("Vacuum complete.")

else:
    print("No addresses found with balance > 1000 BTC.")

conn.close()
