import sqlite3
import re

def check_db():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    
    print("--- 10 Addresses with fail_att ---")
    cursor.execute("SELECT address, fail_att, brainwallet_scanned FROM addresses WHERE fail_att != '' LIMIT 10")
    for row in cursor.fetchall():
        print(f"Address: {row[0]}, Fail_att: {row[1]}, Brainwallet_scanned: {row[2]}")
        
    print("\n--- Addresses ready for bruteforce (CORRECTED GLOB) ---")
    stage_filter = (
        "fail_att GLOB '*[[]1.[3-9][]]*' AND "
        "fail_att GLOB '*[[]2.[3-9][]]*' AND "
        "fail_att GLOB '*[[]3.[3-9][]]*' AND "
        "fail_att GLOB '*[[]4.[3-9][]]*' AND "
        "fail_att GLOB '*[[]5.[3-9][]]*' AND "
        "fail_att GLOB '*[[]6.[3-9][]]*' AND "
        "fail_att GLOB '*[[]7.[3-9][]]*'"
    )
    cursor.execute(f"SELECT COUNT(*) FROM addresses WHERE {stage_filter}")
    print(f"Count ready for bruteforce: {cursor.fetchone()[0]}")
    
    print("\n--- Addresses ready for brainwallet ---")
    cursor.execute("SELECT COUNT(*) FROM addresses WHERE brainwallet_scanned = 0 AND status != 'Compromised'")
    print(f"Count ready for brainwallet: {cursor.fetchone()[0]}")
    
    conn.close()

if __name__ == '__main__':
    check_db()
