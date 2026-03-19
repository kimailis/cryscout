import requests
import json
import sqlite3
import time

def fetch_blockchair_targets(limit=100, offset=0):
    # 10 to 20 BTC in satoshis
    min_bal = 10 * 100000000
    max_bal = 20 * 100000000
    # Dormant for 10+ years (before 2016-03-19)
    last_seen_max = "2016-03-19"
    
    url = f"https://api.blockchair.com/bitcoin/addresses"
    params = {
        "q": f"balance({min_bal}..{max_bal}),time_last_seen(..{last_seen_max}),spent(1..)",
        "limit": limit,
        "offset": offset,
        "export": "address,balance,time_last_seen,spending_transaction_count"
    }
    
    print(f"Fetching from Blockchair: offset={offset}...")
    try:
        resp = requests.get(url, params=params, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            return data.get('data', [])
        else:
            print(f"Error: {resp.status_code} - {resp.text}")
            return []
    except Exception as e:
        print(f"Exception: {e}")
        return []

def main():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    
    total_needed = 4000
    total_ingested = 0
    batch_size = 100
    
    # We'll try to fetch in batches
    for offset in range(0, total_needed, batch_size):
        targets = fetch_blockchair_targets(limit=batch_size, offset=offset)
        if not targets:
            print("No more targets found or error occurred.")
            break
            
        for t in targets:
            addr = t['address']
            balance = t['balance'] / 100000000.0
            last_seen = t['time_last_seen']
            
            # Potential weakness: Dormant 10y+ with exposed pubkey
            weakness = f"Dormant 10y+ (Last seen: {last_seen})"
            
            cursor.execute('''
                INSERT OR IGNORE INTO addresses (address, balance, status, last_seen, potential_weakness, sigs_fetched, sigs_scanned)
                VALUES (?, ?, 'Dormant', ?, ?, 0, 0)
            ''', (addr, balance, last_seen, weakness))
            
            if cursor.rowcount > 0:
                total_ingested += 1
        
        conn.commit()
        print(f"Ingested {total_ingested} targets so far...")
        
        if len(targets) < batch_size:
            break
            
        # Respect API rate limits
        time.sleep(2)

    conn.close()
    print(f"Finished. Total ingested: {total_ingested}")

if __name__ == "__main__":
    main()
