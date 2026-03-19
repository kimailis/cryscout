import sqlite3
import csv
import re

def clean_balance(b_str):
    if not b_str: return 0.0
    match = re.search(r'([\d,.]+)', b_str)
    if match:
        return float(match.group(1).replace(',', ''))
    return 0.0

conn = sqlite3.connect('cryscout.db')
cursor = conn.cursor()

TARGET_COUNT = 8000

imported = 0
print(f"Scanning master CSV for all available targets...")

with open('master_address_tracking.csv', mode='r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if imported >= TARGET_COUNT:
            break
            
        addr = row['Address']
        bal_str = row['Current Balance'] or row['Balance_dormant'] or ""
        balance = clean_balance(bal_str)
        
        status = row.get('Status', 'Dormant')
        label = row.get('Label', '')
        rank = row.get('Rank', 0)
        type_ = row.get('Type', 'Legacy (1...)')
        weakness = "High Analysis Priority (Lattice/Bias)"
        
        cursor.execute('''
            INSERT OR IGNORE INTO addresses (address, balance, status, label, rank, type, potential_weakness, sigs_fetched, sigs_scanned)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)
        ''', (addr, balance, status, label, rank, type_, weakness))
        
        if cursor.rowcount > 0:
            imported += 1

conn.commit()
conn.close()
print(f"Successfully imported {imported} new targets without balance restriction.")
