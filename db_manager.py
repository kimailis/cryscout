import sqlite3
import os
import json
import time
import random
from datetime import datetime

DB_NAME = 'cryscout.db'

def get_connection(timeout=30.0):
    """Get connection with a longer timeout for concurrent access."""
    conn = sqlite3.connect(DB_NAME, timeout=timeout)
    # Enable Write-Ahead Logging for better concurrency
    try:
        conn.execute('PRAGMA journal_mode=WAL')
    except:
        pass
    return conn

def execute_with_retry(func, *args, **kwargs):
    """Execute a DB function with retries on lock."""
    max_retries = 5
    for i in range(max_retries):
        try:
            return func(*args, **kwargs)
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() and i < max_retries - 1:
                time.sleep(0.1 * (2 ** i) + random.random() * 0.1)
                continue
            raise

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
        sigs_fetched BOOLEAN DEFAULT 0,
        sigs_scanned BOOLEAN DEFAULT 0,
        analyzed BOOLEAN DEFAULT 0,
        nonces_checked BOOLEAN DEFAULT 0,
        processing_by TEXT,
        processing_since DATETIME,
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
        UNIQUE(address, txid, vin, r_hex, s_hex)
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
    
    # Worker status table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS worker_status (
        worker_id TEXT PRIMARY KEY,
        task TEXT,
        cpu_usage REAL,
        ram_usage REAL,
        last_heartbeat DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.commit()
    conn.close()

def claim_address(worker_id, stage=None, limit=1, extra_filter=None):
    """Claim the most vulnerable addresses for a worker."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Define stage filter for continuous looping and improvement
    stage_filter = "analyzed = 0"
    if stage == 'fetching':
        # Re-fetch data every 7 days to find new txs or leaks
        stage_filter = "(sigs_fetched = 0 OR last_updated < datetime('now', '-7 days'))"
    elif stage == 'scanning':
        # Re-scan every 3 days with potentially improved dictionaries/patterns
        stage_filter = "(sigs_scanned = 0 OR last_updated < datetime('now', '-3 days')) AND sigs_fetched = 1"
    elif stage == 'analyzing':
        # Re-analyze every 1 day with potentially deeper lattice/algebraic parameters
        stage_filter = "(analyzed = 0 OR last_updated < datetime('now', '-1 day')) AND sigs_fetched = 1"
    
    # Exclude already compromised addresses
    stage_filter = f"({stage_filter}) AND IFNULL(status, '') != 'Compromised'"

    if extra_filter:
        stage_filter += f" AND {extra_filter}"

    cursor.execute(f'''
    UPDATE addresses 
    SET processing_by = ?, processing_since = CURRENT_TIMESTAMP
    WHERE address IN (
        SELECT address FROM addresses 
        WHERE (processing_by IS NULL OR processing_since < datetime('now', '-30 minutes'))
        AND {stage_filter}
        ORDER BY current_balance DESC, transactions DESC
        LIMIT ?
    )
    ''', (worker_id, limit))
    
    conn.commit()
    
    cursor.execute("SELECT address FROM addresses WHERE processing_by = ?", (worker_id,))
    addresses = [row[0] for row in cursor.fetchall()]
    conn.close()
    return addresses

def mark_stage_done(address, stage, worker_id):
    """Mark a specific stage as done for an address."""
    conn = get_connection()
    cursor = conn.cursor()
    column = "analyzed"
    if stage == 'fetching':
        column = "sigs_fetched"
    elif stage == 'scanning':
        column = "sigs_scanned"
    elif stage == 'analyzing':
        column = "analyzed"

    cursor.execute(f'''
    UPDATE addresses 
    SET {column} = 1, processing_by = NULL, processing_since = NULL, last_updated = CURRENT_TIMESTAMP
    WHERE address = ? AND processing_by = ?
    ''', (address, worker_id))
    conn.commit()
    conn.close()

def release_address(address, worker_id, mark_done=False):
    """Release a claimed address."""
    conn = get_connection()
    cursor = conn.cursor()
    if mark_done:
        cursor.execute('''
        UPDATE addresses 
        SET processing_by = NULL, processing_since = NULL, analyzed = 1 
        WHERE address = ? AND processing_by = ?
        ''', (address, worker_id))
    else:
        cursor.execute('''
        UPDATE addresses 
        SET processing_by = NULL, processing_since = NULL 
        WHERE address = ? AND processing_by = ?
        ''', (address, worker_id))
    conn.commit()
    conn.close()

def update_worker_status(worker_id, task, cpu=0.0, ram=0.0):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO worker_status (worker_id, task, cpu_usage, ram_usage, last_heartbeat)
    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(worker_id) DO UPDATE SET
    task=excluded.task, cpu_usage=excluded.cpu_usage, ram_usage=excluded.ram_usage, last_heartbeat=CURRENT_TIMESTAMP
    ''', (worker_id, task, cpu, ram))
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

def save_signatures(address, sigs_list):
    conn = get_connection()
    cursor = conn.cursor()
    
    for sig in sigs_list:
        r_int = str(sig['r'])
        s_int = str(sig['s'])
        z_int = str(sig['z'])
        r_hex = hex(sig['r'])[2:].zfill(64)
        s_hex = hex(sig['s'])[2:].zfill(64)
        z_hex = hex(sig['z'])[2:].zfill(64)
        txid = sig['txid']
        vin = sig.get('vin', 0)
        pubkey = sig.get('pubkey', '')
        
        # Calculate r_bits (useful for bias detection)
        r_bits = sig['r'].bit_length()
        
        cursor.execute('''
        INSERT OR IGNORE INTO signatures (address, txid, vin, r_hex, s_hex, z_hex, pubkey_hex, r_int, s_int, z_int, r_bits)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (address, txid, vin, r_hex, s_hex, z_hex, pubkey, r_int, s_int, z_int, r_bits))
    
    conn.commit()
    conn.close()

def get_target_addresses(limit=10, only_unprocessed=True):
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT address FROM addresses"
    if only_unprocessed:
        query += " WHERE analyzed = 0"
    query += f" LIMIT {limit}"
    
    cursor.execute(query)
    addresses = [row[0] for row in cursor.fetchall()]
    conn.close()
    return addresses

def mark_analyzed(address, status=True):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE addresses SET analyzed = ? WHERE address = ?", (1 if status else 0, address))
    conn.commit()
    conn.close()

def get_signatures(address):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT r_int, s_int, z_int, txid FROM signatures WHERE address = ?", (address,))
    rows = cursor.fetchall()
    conn.close()
    return [{'r': int(r), 's': int(s), 'z': int(z), 'txid': txid} for r, s, z, txid in rows]

def add_recovered_key(address, privkey_hex, wif='', method='Lattice'):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO recovered_keys (address, privkey_hex, wif, method)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(address) DO UPDATE SET
    privkey_hex=excluded.privkey_hex,
    wif=excluded.wif,
    method=excluded.method,
    found_at=CURRENT_TIMESTAMP
    ''', (address, privkey_hex, wif, method))
    
    # Also update address table
    cursor.execute('''
    UPDATE addresses 
    SET vulnerability = 'Recovered Private Key',
        status = 'Compromised'
    WHERE address = ?
    ''', (address,))
    
    conn.commit()
    conn.close()

def find_all_addresses():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT address FROM addresses")
    addresses = [row[0] for row in cursor.fetchall()]
    conn.close()
    return addresses

if __name__ == "__main__":
    init_db()
    print(f"Database {DB_NAME} initialized.")
