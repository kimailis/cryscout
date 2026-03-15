import sqlite3
import json
from tx_preimage_reconstructor import extract_sigs_with_real_z
from db_manager import save_signatures, mark_stage_done

target = "1GR9qNz7zgtaW5HwwVpEJWMnGWhsbsieCG"

def fetch_all_for_target():
    print(f"Fetching ALL signatures for {target}...")
    sigs = extract_sigs_with_real_z(target, max_sigs=10000)
    if sigs:
        print(f"Found {len(sigs)} signatures. Saving...")
        save_signatures(target, sigs)
        print("Sigs saved.")
        
        # Manually update pubkey for ALL sigs we just found
        pubkey = "03a66af64bd473394550d16584921c82a18d7efff5e521bce6ea9e2b50dc8606dc"
        conn = sqlite3.connect('cryscout.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE signatures SET pubkey_hex = ? WHERE address = ?', (pubkey, target))
        conn.commit()
        conn.close()
        print(f"Pubkey updated for {target}")
    else:
        print(f"No signatures found for {target}")

if __name__ == "__main__":
    fetch_all_for_target()
