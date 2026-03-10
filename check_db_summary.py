
import sqlite3
import json

def summarize_findings():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    
    print("--- CryScout Database Summary ---")
    
    # Total addresses
    cursor.execute("SELECT COUNT(*) FROM addresses")
    total = cursor.fetchone()[0]
    print(f"Total addresses in DB: {total}")
    
    # Analyzed addresses
    cursor.execute("SELECT COUNT(*) FROM addresses WHERE analyzed = 1")
    analyzed = cursor.fetchone()[0]
    print(f"Analyzed addresses: {analyzed}")
    
    # Recovered keys
    cursor.execute("SELECT address, privkey_hex, method, found_at FROM recovered_keys")
    keys = cursor.fetchall()
    print(f"\nRecovered Keys ({len(keys)}):")
    for addr, priv, method, found_at in keys:
        print(f"  - Address: {addr}")
        print(f"    Method:  {method}")
        print(f"    Key:     {priv[:10]}...{priv[-10:]}")
        print(f"    Found:   {found_at}")
        
    # Vulnerabilities
    cursor.execute("SELECT address, type, severity, found_at FROM vulnerabilities")
    vulns = cursor.fetchall()
    print(f"\nVulnerabilities ({len(vulns)}):")
    for addr, vtype, severity, found_at in vulns:
        print(f"  - [{severity}] {vtype} for {addr} ({found_at})")
        
    # Stats from addresses table
    cursor.execute("SELECT vulnerability, COUNT(*) FROM addresses WHERE vulnerability IS NOT NULL AND vulnerability != 'None' GROUP BY vulnerability")
    vuln_stats = cursor.fetchall()
    if vuln_stats:
        print("\nVulnerability Stats (Address Table):")
        for v, count in vuln_stats:
            print(f"  - {v}: {count}")

    conn.close()

if __name__ == '__main__':
    summarize_findings()
