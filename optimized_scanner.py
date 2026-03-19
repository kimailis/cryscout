import requests
import sqlite3
import time

def get_block_addrs(height):
    url = f"https://blockchain.info/rawblock/{height}"
    try:
        resp = requests.get(url, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            addrs = set()
            for tx in data.get('tx', []):
                # We want addresses that have SPENT (vulnerable)
                for inp in tx.get('inputs', []):
                    prev = inp.get('prev_out', {})
                    if prev and 'addr' in prev:
                        addrs.add(prev['addr'])
            return list(addrs)
    except:
        pass
    return []

def check_batch(addrs):
    if not addrs: return []
    q = '|'.join(addrs)
    url = f"https://blockchain.info/multiaddr?active={q}&limit=0"
    try:
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            results = []
            for info in data.get('addresses', []):
                bal = info.get('final_balance', 0) / 100000000.0
                sent = info.get('total_sent', 0)
                if 5.0 <= bal <= 15.0 and sent > 0:
                    results.append({'address': info['address'], 'balance': bal})
            return results
    except:
        pass
    return []

def is_dormant(addr):
    # Check if last transaction was > 10 years ago (before 2016-03-19)
    url = f"https://blockchain.info/rawaddr/{addr}?limit=1"
    max_ts = 1458345600 # 2016-03-19
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            txs = data.get('txs', [])
            if txs:
                last_tx_time = txs[0].get('time', 0)
                return last_tx_time < max_ts
    except:
        pass
    return False

def main():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    
    found_total = 0
    target_goal = 3000
    
    # Randomly sample blocks from 2011 to 2014
    import random
    
    checked_blocks = set()
    
    print(f"Starting optimized blockchain scan for {target_goal} targets...")
    
    while found_total < target_goal:
        h = random.randint(150000, 350000)
        if h in checked_blocks: continue
        checked_blocks.add(h)
        
        print(f"Scanning block {h}...")
        addrs = get_block_addrs(h)
        if not addrs:
            time.sleep(1)
            continue
            
        print(f"  -> Found {len(addrs)} candidates. Checking balances...")
        
        # Filter for legacy only
        legacy_addrs = [a for a in addrs if a.startswith('1')]
        
        batch_size = 100
        for i in range(0, len(legacy_addrs), batch_size):
            batch = legacy_addrs[i:i+batch_size]
            matches = check_batch(batch)
            
            for m in matches:
                addr = m['address']
                bal = m['balance']
                
                print(f"    [*] Potential match: {addr} ({bal} BTC). Checking dormancy...")
                if is_dormant(addr):
                    cursor.execute('''
                        INSERT OR IGNORE INTO addresses (address, balance, status, potential_weakness, sigs_fetched, sigs_scanned)
                        VALUES (?, ?, 'Dormant', 'Vulnerable Dormant (5-15 BTC)', 0, 0)
                    ''', (addr, bal))
                    if cursor.rowcount > 0:
                        found_total += 1
                        print(f"      [+] TARGET ADDED ({found_total}/{target_goal}): {addr}")
                        conn.commit()
                time.sleep(0.5)
            
            time.sleep(1) # Be nice to multiaddr API
            
        time.sleep(1) # Be nice to rawblock API

    conn.close()

if __name__ == "__main__":
    main()
