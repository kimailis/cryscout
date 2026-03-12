#!/usr/bin/env python3
import struct
import hashlib
import sqlite3
import os
import binascii
from db_manager import get_connection

# SECP256K1 Curve Order
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def parse_der_signature(sig_hex):
    """Extract r and s from a DER-encoded signature."""
    try:
        sig_bytes = bytes.fromhex(sig_hex)
        if sig_bytes[0] != 0x30: return None, None
        
        r_len = sig_bytes[3]
        r_bytes = sig_bytes[4:4+r_len]
        
        s_len = sig_bytes[4+r_len+1]
        s_bytes = sig_bytes[4+r_len+2:4+r_len+2+s_len]
        
        r = int.from_bytes(r_bytes, 'big')
        s = int.from_bytes(s_bytes, 'big')
        return r, s
    except:
        return None, None

def extract_signatures_from_block(block_data, height):
    """
    Advanced signature extraction from raw block data.
    Populates the local database with research-grade metadata.
    """
    # This is a conceptual integration. 
    # In a real pipeline, this would be called by the block parser.
    pass

def query_attack_candidates():
    """Identifies pubkeys with multiple signatures for cryptanalysis."""
    conn = get_connection()
    cursor = conn.cursor()
    
    print("\n--- Cryptanalysis Attack Candidates (Local DB) ---")
    query = '''
    SELECT pubkey_hex, COUNT(*) as sig_count, GROUP_CONCAT(DISTINCT address) as addresses
    FROM signatures
    WHERE pubkey_hex IS NOT NULL AND pubkey_hex != ''
    GROUP BY pubkey_hex
    HAVING sig_count >= 2
    ORDER BY sig_count DESC
    LIMIT 20
    '''
    cursor.execute(query)
    rows = cursor.fetchall()
    
    if not rows:
        print("No candidates with multiple signatures found yet.")
    else:
        print(f"{'Pubkey':<66} | {'Sigs':<5} | {'Addresses'}")
        print("-" * 100)
        for row in rows:
            print(f"{row[0]:<66} | {row[1]:<5} | {row[2]}")
            
    conn.close()

if __name__ == "__main__":
    query_attack_candidates()
