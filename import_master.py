import sqlite3
import csv
import re

def clean_balance(b_str):
    if not b_str: return 0.0
    # Extract number from "79,957 BTC" or "79957.27 BTC"
    match = re.search(r'([\d,.]+)', b_str)
    if match:
        return float(match.group(1).replace(',', ''))
    return 0.0

conn = sqlite3.connect('cryscout.db')
cursor = conn.cursor()

with open('master_address_tracking.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        addr = row['Address']
        balance = clean_balance(row['Current Balance'])
        transactions = int(float(row['Transactions'])) if row['Transactions'] else 0
        status = row['Status']
        label = row['Label']
        rank = int(row['Rank']) if row['Rank'] else 0
        type_ = row['Type']
        potential_weakness = row['Potential_Weakness']
        accessibility = row['Accessibility']
        total_received = clean_balance(row['Total Received'])
        total_sent = clean_balance(row['Total Sent'])
        
        cursor.execute('''
            INSERT OR REPLACE INTO addresses (
                address, balance, transactions, status, label, rank, type, 
                potential_weakness, accessibility, total_received, total_sent, sigs_fetched
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        ''', (addr, balance, transactions, status, label, rank, type_, 
              potential_weakness, accessibility, total_received, total_sent))

conn.commit()
conn.close()
print("Imported master addresses.")
