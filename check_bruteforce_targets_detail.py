import sqlite3
import re

def check_db():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    
    stage_filter = (
        "fail_att GLOB '*[1.[3-9]]*' AND "
        "fail_att GLOB '*[2.[3-9]]*' AND "
        "fail_att GLOB '*[3.[3-9]]*' AND "
        "fail_att GLOB '*[4.[3-9]]*' AND "
        "fail_att GLOB '*[5.[3-9]]*' AND "
        "fail_att GLOB '*[6.[3-9]]*' AND "
        "fail_att GLOB '*[7.[3-9]]*'"
    )
    
    print("\n--- Addresses ready for bruteforce (Top 5) ---")
    cursor.execute(f"SELECT address, fail_att FROM addresses WHERE {stage_filter} LIMIT 5")
    for row in cursor.fetchall():
        print(f"Address: {row[0]}, Fail_att: {row[1]}")
    
    conn.close()

if __name__ == '__main__':
    check_db()
