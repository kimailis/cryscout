import sqlite3
import json

def check_findings():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    
    print("--- Stats ---")
    cursor.execute("SELECT COUNT(*) FROM addresses")
    print(f"Total addresses: {cursor.fetchone()[0]}")
    
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    print(f"Total vulnerabilities: {cursor.fetchone()[0]}")
    
    cursor.execute("SELECT COUNT(*) FROM recovered_keys")
    print(f"Total recovered keys: {cursor.fetchone()[0]}")
    
    print("\n--- Vulnerabilities ---")
    cursor.execute("SELECT * FROM vulnerabilities LIMIT 10")
    for row in cursor.fetchall():
        print(row)
        
    print("\n--- Recovered Keys ---")
    cursor.execute("SELECT * FROM recovered_keys LIMIT 10")
    for row in cursor.fetchall():
        print(row)
        
    conn.close()

if __name__ == "__main__":
    check_findings()
