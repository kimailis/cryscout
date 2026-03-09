import csv
import os
import sqlite3
from db_manager import init_db, DB_NAME

def clean_balance(val):
    if not val or val == 'N/A':
        return None
    # Remove commas and 'BTC' or other currency markers
    cleaned = val.replace(',', '').replace(' BTC', '').strip()
    try:
        return float(cleaned)
    except ValueError:
        return None

def robust_int(val):
    if not val or val == 'N/A':
        return None
    try:
        # First convert to float to handle '671.0', then to int
        return int(float(val.replace(',', '')))
    except ValueError:
        return None

def migrate_csv_to_db():
    if not os.path.exists('master_address_tracking.csv'):
        print("master_address_tracking.csv not found. Please run combine_data.py first or ensure the file exists.")
        return

    init_db()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    with open('master_address_tracking.csv', 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    print(f"Migrating {len(rows)} addresses from CSV to DB...")

    for row in rows:
        # Mapping CSV columns to DB columns
        data = {
            'address': row.get('Address'),
            'label': row.get('Label'),
            'rank': robust_int(row.get('Rank')),
            'balance': clean_balance(row.get('Balance')),
            'balance_dormant': clean_balance(row.get('Balance_dormant')),
            'current_balance': clean_balance(row.get('Current Balance')),
            'total_received': clean_balance(row.get('Total Received')),
            'total_sent': clean_balance(row.get('Total Sent')),
            'transactions': robust_int(row.get('Transactions')),
            'first_seen': row.get('First Seen'),
            'last_seen': row.get('Last Seen'),
            'status': row.get('Status'),
            'accessibility': row.get('Accessibility'),
            'type': row.get('Type'),
            'vulnerability': row.get('Vulnerability'),
            'potential_weakness': row.get('Potential_Weakness'),
            'analyzed': 1 if str(row.get('Analyzed')).lower() == 'true' else 0,
            'nonces_checked': 1 if str(row.get('Nonces_Checked')).lower() == 'true' else 0
        }

        columns = list(data.keys())
        placeholders = [':' + col for col in columns]
        
        query = f'''
        INSERT INTO addresses ({", ".join(columns)})
        VALUES ({", ".join(placeholders)})
        ON CONFLICT(address) DO UPDATE SET
        {", ".join([f"{col}=excluded.{col}" for col in columns if col != 'address'])},
        last_updated=CURRENT_TIMESTAMP
        '''
        
        cursor.execute(query, data)

    conn.commit()
    
    # Import vulnerabilities from vulnerabilities_found.txt if it exists
    if os.path.exists('vulnerabilities_found.txt'):
        print("Importing findings from vulnerabilities_found.txt...")
        with open('vulnerabilities_found.txt', 'r') as f:
            for line in f:
                if 'Brainwallet Match:' in line:
                    # Brainwallet Match: phrase -> addr (PK: pk)
                    parts = line.split('->')
                    if len(parts) == 2:
                        phrase = parts[0].replace('Brainwallet Match:', '').strip()
                        addr_part = parts[1].split('(PK:')[0].strip()
                        pk_part = parts[1].split('(PK:')[1].replace(')', '').strip()
                        
                        cursor.execute('''
                        INSERT INTO vulnerabilities (address, type, details, severity)
                        VALUES (?, ?, ?, ?)
                        ''', (addr_part, 'Brainwallet', f"Phrase: {phrase}, PK: {pk_part}", 'High'))
                        
                        cursor.execute('''
                        INSERT INTO recovered_keys (address, privkey_hex, method)
                        VALUES (?, ?, ?)
                        ON CONFLICT(address) DO NOTHING
                        ''', (addr_part, pk_part, 'Brainwallet'))

    # Import bias candidates from bias_candidates.txt if it exists
    if os.path.exists('bias_candidates.txt'):
        print("Importing findings from bias_candidates.txt...")
        with open('bias_candidates.txt', 'r') as f:
            current_finding = {}
            for line in f:
                line = line.strip()
                if not line:
                    if current_finding.get('Address'):
                        cursor.execute('''
                        INSERT INTO vulnerabilities (address, type, txid, details, severity)
                        VALUES (?, ?, ?, ?, ?)
                        ''', (current_finding['Address'], f"Bias ({current_finding.get('Type', 'Unknown')})", 
                              current_finding.get('TX'), f"R-Bits: {current_finding.get('R-Bits')}, Hex: {current_finding.get('Hex')}", 'Medium'))
                    current_finding = {}
                    continue
                
                if ':' in line:
                    k, v = line.split(':', 1)
                    current_finding[k.strip()] = v.strip()

    conn.commit()
    conn.close()
    print("Migration complete.")

if __name__ == "__main__":
    migrate_csv_to_db()
