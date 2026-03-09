import sqlite3
import os
import json
from datetime import datetime

DB_NAME = 'cryscout.db'

def get_connection():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Addresses table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS addresses (
        address TEXT PRIMARY KEY,
        label TEXT,
        rank INTEGER,
        balance REAL,
        balance_dormant REAL,
        current_balance REAL,
        total_received REAL,
        total_sent REAL,
        transactions INTEGER,
        first_seen TEXT,
        last_seen TEXT,
        status TEXT,
        accessibility TEXT,
        type TEXT,
        vulnerability TEXT,
        potential_weakness TEXT,
        analyzed BOOLEAN DEFAULT 0,
        nonces_checked BOOLEAN DEFAULT 0,
        last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Signatures table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS signatures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT,
        txid TEXT,
        vin INTEGER,
        r_hex TEXT,
        s_hex TEXT,
        z_hex TEXT,
        pubkey_hex TEXT,
        r_int TEXT,
        s_int TEXT,
        z_int TEXT,
        r_bits INTEGER,
        is_biased BOOLEAN,
        found_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (address) REFERENCES addresses (address)
    )
    ''')
    
    # Vulnerabilities table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT,
        type TEXT,
        txid TEXT,
        details TEXT,
        severity TEXT,
        found_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (address) REFERENCES addresses (address)
    )
    ''')
    
    # Recovered keys table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS recovered_keys (
        address TEXT PRIMARY KEY,
        privkey_hex TEXT,
        wif TEXT,
        method TEXT,
        found_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (address) REFERENCES addresses (address)
    )
    ''')
    
    conn.commit()
    conn.close()

def upsert_address(address_data):
    conn = get_connection()
    cursor = conn.cursor()
    
    # Dynamically build the query based on provided keys
    columns = list(address_data.keys())
    placeholders = [':' + col for col in columns]
    
    query = f'''
    INSERT INTO addresses ({", ".join(columns)})
    VALUES ({", ".join(placeholders)})
    ON CONFLICT(address) DO UPDATE SET
    {", ".join([f"{col}=excluded.{col}" for col in columns if col != 'address'])},
    last_updated=CURRENT_TIMESTAMP
    '''
    
    cursor.execute(query, address_data)
    conn.commit()
    conn.close()

def add_finding(address, finding_type, txid=None, details=None, severity='Medium'):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO vulnerabilities (address, type, txid, details, severity)
    VALUES (?, ?, ?, ?, ?)
    ''', (address, finding_type, txid, json.dumps(details) if isinstance(details, (dict, list)) else details, severity))
    
    # Also update the address table to mark it as potentially weak
    cursor.execute('''
    UPDATE addresses 
    SET potential_weakness = ? 
    WHERE address = ? AND (potential_weakness IS NULL OR potential_weakness = 'None Identified')
    ''', (f"Found {finding_type}", address))
    
    conn.commit()
    conn.close()

def get_stats():
    conn = get_connection()
    cursor = conn.cursor()
    
    stats = {}
    cursor.execute("SELECT COUNT(*) FROM addresses")
    stats['total'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM addresses WHERE analyzed = 1")
    stats['analyzed'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM addresses WHERE status = 'Dormant'")
    stats['dormant'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    stats['vulnerabilities'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM recovered_keys")
    stats['keys_recovered'] = cursor.fetchone()[0]
    
    conn.close()
    return stats

if __name__ == "__main__":
    init_db()
    print(f"Database {DB_NAME} initialized.")
