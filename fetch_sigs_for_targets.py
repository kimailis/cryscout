import json
import os
from tx_preimage_reconstructor import extract_sigs_with_real_z
from db_manager import init_db, upsert_address, save_signatures, mark_analyzed, get_connection

targets = [
    '1AV4KGCsvtPZ9tG7hvwgb85wJyFd9xdpFv',
    '13kxWCuDWN1gGSe2vPmsSBVXyPfYLMh6M4',
    '1FdPpELnjHfwSM4Nvi7LdYS4S4GVGsLUQY',
    '152kzDqjAVuPBMmJqcWvFbB7qkvigFXSLh',
    '1HDNfSr5ExyGfe77GX681PPZtN2deoewfd'
]

def fetch_and_save():
    init_db()
    
    # Get Spent/Active addresses or those with potential weaknesses from DB
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT address FROM addresses 
        WHERE status = 'Spent/Active' 
        OR label = 'Lattice Target' 
        OR potential_weakness IS NOT NULL
        OR address IN (SELECT address FROM vulnerabilities)
    """)
    db_targets = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    # Combine with hardcoded targets
    all_targets = list(set(targets + db_targets))
    
    for addr in all_targets:
        # Check if we already have sigs for this address in DB
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM signatures WHERE address = ?", (addr,))
        count = cursor.fetchone()[0]
        conn.close()
        
        if count >= 256:
            print(f"Skipping {addr}, already have {count} signatures in DB")
            continue
            
        print(f"Fetching up to 256 sigs for {addr}...")
        
        # Upsert the address into the table first if not there
        upsert_address({'address': addr, 'status': 'Target' if addr in targets else 'Spent/Active'})
        
        sigs = extract_sigs_with_real_z(addr, max_pages=100, max_sigs=256)
        if sigs:
            save_signatures(addr, sigs)
            print(f"Saved {len(sigs)} sigs to database for {addr}")
            mark_analyzed(addr, True)

if __name__ == "__main__":
    fetch_and_save()
