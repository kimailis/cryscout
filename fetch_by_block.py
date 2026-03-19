import requests
import re
import sqlite3
import time

def scrape_block(height):
    url = f"https://bitinfocharts.com/bitcoin/block/{height}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            # Extract addresses and balances
            # Pattern: <a href="https://bitinfocharts.com/bitcoin/address/1...">1...</a></td><td data-val="1000000000">10 BTC</td>
            addresses = re.findall(r'address/([13][a-km-zA-HJ-NP-Z1-9]{25,34})', resp.text)
            return list(set(addresses))
    except:
        pass
    return []

def get_balance(addr):
    # Use a simple API to check balance
    try:
        resp = requests.get(f"https://blockchain.info/q/addressbalance/{addr}", timeout=5)
        if resp.status_code == 200:
            return int(resp.text) / 100000000.0
    except:
        pass
    return 0.0

def main():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    
    found = 0
    needed = 3000
    
    # Start from an old block height (e.g., block 200,000 from 2012)
    current_height = 200000
    
    while found < needed and current_height > 100000:
        print(f"Scraping block {current_height}...")
        addrs = scrape_block(current_height)
        for addr in addrs:
            if found >= needed: break
            
            bal = get_balance(addr)
            if 5.0 <= bal <= 15.0:
                # Check dormancy (if last seen is old)
                # For simplicity, if it's in an old block and has balance, it might be dormant.
                # We can verify dormancy later or just assume for now.
                
                cursor.execute('''
                    INSERT OR IGNORE INTO addresses (address, balance, status, potential_weakness, sigs_fetched, sigs_scanned, vulnerability_score)
                    VALUES (?, ?, 'Dormant', 'Satoshi-Era Dormant (5-15 BTC)', 0, 0, 1.0)
                ''', (addr, bal))
                if cursor.rowcount > 0:
                    found += 1
                    print(f"Found {found}/{needed}: {addr} ({bal} BTC)")
        
        current_height -= 1
        conn.commit()
        time.sleep(1) # Respect bitinfocharts

    conn.close()

if __name__ == "__main__":
    main()
