import sqlite3

def check_validity():
    try:
        conn = sqlite3.connect('cryscout.db')
        cursor = conn.cursor()
        
        # Check some records
        cursor.execute("SELECT address, balance, current_balance, type, vulnerability_score FROM addresses WHERE balance > 0 LIMIT 10")
        rows = cursor.fetchall()
        print("Sample addresses with balance > 0:")
        for row in rows:
            print(f"Address: {row[0]}, Balance: {row[1]}, Current: {row[2]}, Type: {row[3]}, Score: {row[4]}")

        # Check balance distribution
        cursor.execute("SELECT MIN(balance), MAX(balance), AVG(balance), COUNT(*) FROM addresses WHERE balance > 0")
        stats = cursor.fetchone()
        print(f"\nStats for addresses with balance > 0:")
        print(f"Min: {stats[0]}, Max: {stats[1]}, Avg: {stats[2]}, Count: {stats[3]}")

        # Check address count
        cursor.execute("SELECT COUNT(*) FROM addresses")
        total_count = cursor.fetchone()[0]
        print(f"\nTotal addresses in system: {total_count}")

        # Check total addresses
        cursor.execute("SELECT COUNT(*) FROM addresses")
        total_count = cursor.fetchone()[0]
        print(f"Total addresses in DB: {total_count}")

        conn.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_validity()
