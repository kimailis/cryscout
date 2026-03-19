import sqlite3
import re

def is_valid_btc_address(address):
    # Base58 (Legacy 1... and P2SH 3...)
    # Excludes 0, O, I, l
    if re.match(r"^[13][1-9A-HJ-NP-Za-km-z]{25,34}$", address):
        return True
    # Bech32 (SegWit bc1...)
    # Use bech32 charset (all lowercase + digits except 1, b, i, o)
    if re.match(r"^bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{39,59}$", address):
        return True
    return False

def check_db_validity():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT address, type, balance FROM addresses")
    rows = cursor.fetchall()
    
    invalid_format = []
    for address, addr_type, balance in rows:
        if not is_valid_btc_address(address):
            invalid_format.append(address)
            
    print(f"Checked {len(rows)} addresses.")
    print(f"Invalid format: {len(invalid_format)}")
    if invalid_format:
        print(f"Sample invalid: {invalid_format[:10]}")
    
    # All addresses are now valid regardless of balance
    cursor.execute("SELECT COUNT(*) FROM addresses WHERE balance > 0")
    with_balance = cursor.fetchone()[0]
    print(f"Addresses with balance > 0: {with_balance}")
    conn.close()

if __name__ == "__main__":
    check_db_validity()
