import requests
import sqlite3
import time

def fetch_targets(limit=100, offset=0):
    # Dormant for 10 years (before 2016-03-19)
    # Balance between 5 and 15 BTC (500,000,000 to 1,500,000,000 Satoshis)
    # Must have spent transactions (to have signatures)
    
    url = f"https://api.blockchair.com/bitcoin/addresses"
    params = {
        "q": "time_last_seen(..2016-03-19),balance(500000000..1500000000),spending_transaction_count(1..)",
        "limit": limit,
        "offset": offset,
        "export": "address,balance,time_last_seen,spending_transaction_count"
    }
    
    print(f"Fetching from Blockchair: offset={offset}...")
    try:
        resp = requests.get(url, params=params, timeout=30)
        if resp.status_code == 200:
            return resp.json().get('data', [])
        else:
            print(f"Error: {resp.status_code} - {resp.text}")
            return []
    except Exception as e:
        print(f"Exception: {e}")
        return []

def main():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    
    total_to_import = 3000
    total_imported = 0
    batch_size = 100
    
    for offset in range(0, 10000, batch_size): # Check up to 10k to find 3000
        targets = fetch_targets(limit=batch_size, offset=offset)
        if not targets:
            print("No more targets found or error occurred.")
            break
            
        for t in targets:
            if total_imported >= total_to_import:
                break
                
            addr = t['address']
            balance = t['balance'] / 100000000.0
            last_seen = t['time_last_seen']
            tx_count = t['spending_transaction_count']
            
            # These are our "vulnerable" era targets
            weakness = f"10-Year Dormant (Era RNG Check) | Bal: {balance} BTC | {tx_count} TXs"
            
            cursor.execute('''
                INSERT OR IGNORE INTO addresses (address, balance, status, last_seen, potential_weakness, sigs_fetched, sigs_scanned, vulnerability_score)
                VALUES (?, ?, 'Dormant', ?, ?, 0, 0, 1.0)
            ''', (addr, balance, last_seen, weakness))
            
            if cursor.rowcount > 0:
                total_imported += 1
        
        conn.commit()
        print(f"Total Imported: {total_imported}")
        
        if total_imported >= total_to_import:
            break
            
        if len(targets) < batch_size:
            break
            
        # Blockchair limit
        time.sleep(2)

    conn.close()
    print(f"Finished. Total imported: {total_imported}")

if __name__ == "__main__":
    main()
