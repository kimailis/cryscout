#!/usr/bin/env python3
"""
Clean duplicate signatures from the DB and identify truly exploitable R-reuse.
Also shows which dormant addresses have spending history (and thus extractable sigs).
"""
import sqlite3
from db_manager import get_connection

def dedup_signatures():
    conn = get_connection()
    c = conn.cursor()
    
    # Count before
    c.execute("SELECT COUNT(*) FROM signatures")
    before = c.fetchone()[0]
    
    # Find exact duplicates (same address, txid, vin, r, s)
    c.execute("""
        DELETE FROM signatures WHERE rowid NOT IN (
            SELECT MIN(rowid) FROM signatures 
            GROUP BY address, txid, vin, r_hex, s_hex
        )
    """)
    removed = c.rowcount
    conn.commit()
    
    c.execute("SELECT COUNT(*) FROM signatures")
    after = c.fetchone()[0]
    print(f"Dedup: {before} -> {after} ({removed} duplicates removed)")
    
    # Now find REAL R-reuse (same R, different Z within same address)
    c.execute("""
        SELECT a.address, a.r_hex, a.txid, a.z_int, b.txid, b.z_int
        FROM signatures a
        JOIN signatures b ON a.address = b.address AND a.r_hex = b.r_hex 
            AND a.rowid < b.rowid AND a.z_int != b.z_int
    """)
    real_reuse = c.fetchall()
    print(f"\nREAL R-reuse (different Z): {len(real_reuse)} pairs")
    for row in real_reuse:
        print(f"  {row[0][:20]}... R={row[1][:16]}...")
        print(f"    TX1={row[2][:16]}... Z1={str(row[3])[:16]}...")
        print(f"    TX2={row[4][:16]}... Z2={str(row[5])[:16]}...")
    
    # Clean invalid vulnerability records that were based on duplicate sigs
    c.execute("DELETE FROM vulnerabilities WHERE type = 'R-Reuse (Same Z)'")
    removed_vulns = c.rowcount
    c.execute("DELETE FROM vulnerabilities WHERE type = 'R-Reuse'")
    removed_vulns += c.rowcount
    conn.commit()
    print(f"\nRemoved {removed_vulns} stale R-Reuse vulnerability records (will re-scan)")
    
    conn.close()

def show_analysis_targets():
    conn = get_connection()
    c = conn.cursor()
    
    # Dormant addresses that are actually "Spent/Active" (have outgoing TXes = have sigs)
    c.execute("""
        SELECT address, current_balance, balance, label, status
        FROM addresses 
        WHERE status = 'Spent/Active'
        ORDER BY COALESCE(current_balance, balance, 0) DESC
    """)
    spent = c.fetchall()
    print(f"\n{'='*60}")
    print(f"Spent/Active addresses (have spending TXes = extractable sigs): {len(spent)}")
    for row in spent[:20]:
        bal = row[1] if row[1] else row[2]
        print(f"  {row[0][:30]}... bal={bal} label={row[3]}")
    
    # Addresses with sigs already
    c.execute("""
        SELECT s.address, COUNT(*) as sig_count, a.status, 
               COALESCE(a.current_balance, a.balance, 0) as bal
        FROM signatures s
        LEFT JOIN addresses a ON s.address = a.address
        GROUP BY s.address
        ORDER BY sig_count DESC
    """)
    with_sigs = c.fetchall()
    print(f"\nAddresses with signatures extracted: {len(with_sigs)}")
    for row in with_sigs:
        print(f"  {row[0][:30]}... sigs={row[1]} status={row[2]} bal={row[3]}")
    
    # Dormant addresses - check how many have any spending history at all
    c.execute("""
        SELECT COUNT(*) FROM addresses 
        WHERE status = 'Dormant' AND transactions > 1
    """)
    dormant_with_txs = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM addresses WHERE status = 'Dormant'")
    total_dormant = c.fetchone()[0]
    
    print(f"\nDormant addresses: {total_dormant}")
    print(f"  With >1 transaction (may have spending TXes): {dormant_with_txs}")
    
    c.execute("""
        SELECT address, balance, transactions, type 
        FROM addresses 
        WHERE status = 'Dormant' AND transactions > 1
        ORDER BY balance DESC
        LIMIT 15
    """)
    rows = c.fetchall()
    print(f"\nTop dormant with multiple transactions:")
    for row in rows:
        print(f"  {row[0][:30]}... bal={row[1]} txs={row[2]} type={row[3]}")
    
    conn.close()

if __name__ == "__main__":
    dedup_signatures()
    show_analysis_targets()
