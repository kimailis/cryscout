import sqlite3
import json
import collections
from ecdsa import SECP256k1
from check_lsb_system import check_lsb_system

def check_all_lsb():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT address, COUNT(*) as c 
        FROM signatures 
        GROUP BY address 
        HAVING c >= 5 
        ORDER BY c DESC
    ''')
    targets = cursor.fetchall()
    
    for address, count in targets:
        cursor.execute('SELECT r_int, s_int, z_int FROM signatures WHERE address = ?', (address,))
        rows = cursor.fetchall()
        sigs = [{'r': int(r), 's': int(s), 'z': int(z)} for r, s, z in rows]
        
        print(f"\n--- Testing {address} ({count} sigs) ---")
        results = check_lsb_system(sigs, max_bits=20)
        if results:
            print(f"!!! FOUND POTENTIAL BIAS for {address} !!!")
            
    conn.close()

if __name__ == "__main__":
    check_all_lsb()
