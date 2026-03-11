import sqlite3

def check_db():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    
    # Intended logic: [1.3], [1.4], etc.
    # GLOB uses [[] for literal [, []] for literal ]
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
    print(f"Count ready for bruteforce (CORRECTED GLOB): {cursor.fetchone()[0]}")
    
    # Let's also check one that SHOULD match if we manually update it
    print("\nSimulating an address that meets the criteria...")
    addr = "1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF"
    fake_fail_att = "[1.3],[2.4],[3.5],[4.6],[5.7],[6.8],[7.9]"
    
    cursor.execute("SELECT 1 WHERE ? GLOB '*[[]1.[3-9][]]*'", (fake_fail_att,))
    print(f"Does {fake_fail_att} match '*[[]1.[3-9][]]*'? {'Yes' if cursor.fetchone() else 'No'}")
    
    conn.close()

if __name__ == '__main__':
    check_db()
