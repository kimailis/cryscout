import requests
import sqlite3
import time

def get_block_addresses(height):
    url = f"https://blockchain.info/rawblock/{height}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            addresses = set()
            for tx in data.get('tx', []):
                for out in tx.get('out', []):
                    addr = out.get('addr')
                    if addr:
                        addresses.add(addr)
            return list(addresses)
    except:
        pass
    return []

def get_balance(addr):
    try:
        # Use the query API which is faster and has higher limits
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
    
    # Blocks from late 2010 to 2011 are good for "dormant" targets
    # Block 100,000 is Dec 2010
    # Block 150,000 is Nov 2011
    current_height = 100000
    
    while found < needed and current_height < 200000:
        print(f"Scanning block {current_height}...")
        addrs = get_block_addresses(current_height)
        for addr in addrs:
            if found >= needed: break
            
            # Heuristic: only check addresses that look like legacy (1...)
            if not addr.startswith('1'): continue
            
            bal = get_balance(addr)
            if 5.0 <= bal <= 15.0:
                # To ensure dormancy, we can check if it has any recent transactions
                # For now, we flag it as "Satoshi-Era Candidate"
                cursor.execute('''
                    INSERT OR IGNORE INTO addresses (address, balance, status, potential_weakness, sigs_fetched, sigs_scanned, vulnerability_score)
                    VALUES (?, ?, 'Dormant', 'Satoshi-Era Dormant (5-15 BTC)', 0, 0, 1.0)
                ''', (addr, bal))
                if cursor.rowcount > 0:
                    found += 1
                    print(f"  -> Found {found}/{needed}: {addr} ({bal} BTC)")
        
        current_height += 1
        conn.commit()
        time.sleep(0.5) # Be kind to blockchain.info

    conn.close()

if __name__ == "__main__":
    main()
