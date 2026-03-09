from db_manager import get_stats, get_connection
import json

def generate_report():
    stats = get_stats()
    print("=== CryScout Database Report ===")
    print(f"Total Addresses: {stats['total']}")
    print(f"Analyzed: {stats['analyzed']}")
    print(f"Vulnerabilities Found: {stats['vulnerabilities']}")
    print(f"Keys Recovered: {stats['keys_recovered']}")
    
    conn = get_connection()
    cursor = conn.cursor()
    
    # List vulnerabilities
    print("\n--- Vulnerabilities Detail ---")
    cursor.execute("SELECT address, type, severity, found_at FROM vulnerabilities ORDER BY found_at DESC")
    rows = cursor.fetchall()
    if rows:
        for row in rows:
            print(f"[{row[2]}] {row[1]} found for {row[0]} at {row[3]}")
    else:
        print("No vulnerabilities recorded.")
        
    # List recovered keys
    print("\n--- Recovered Keys ---")
    cursor.execute("SELECT address, privkey_hex, method, found_at FROM recovered_keys")
    rows = cursor.fetchall()
    if rows:
        for row in rows:
            print(f"SUCCESS: Key found for {row[0]} via {row[2]} at {row[3]}")
            print(f"  Key: {row[1]}")
    else:
        print("No keys recovered yet.")
        
    # List top targets by signature count
    print("\n--- Top Targets by Signature Count ---")
    cursor.execute("SELECT address, COUNT(*) as count FROM signatures GROUP BY address ORDER BY count DESC LIMIT 10")
    rows = cursor.fetchall()
    for row in rows:
        print(f"{row[0]}: {row[1]} signatures")
        
    conn.close()

if __name__ == "__main__":
    generate_report()
