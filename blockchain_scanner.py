import requests
import time
import random

def get_block_addresses(block_height):
    url = f"https://blockchain.info/rawblock/{block_height}"
    try:
        resp = requests.get(url, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            addresses = set()
            for tx in data.get('tx', []):
                for out in tx.get('out', []):
                    if 'addr' in out:
                        addresses.add(out['addr'])
            return list(addresses)
    except:
        pass
    return []

def check_address(address):
    url = f"https://blockchain.info/rawaddr/{address}?limit=0"
    try:
        resp = requests.get(url, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            balance = data.get('final_balance', 0) / 100000000.0
            total_sent = data.get('total_sent', 0)
            
            # Criteria: Any balance, any activity
            if total_sent > 0 or balance > 0:
                # Check dormancy (last transaction > 10 years ago)
                # Max timestamp for 10 years ago (approx 2016-03-19)
                max_ts = 1458345600 
                last_tx_ts = 0
                for tx in data.get('txs', []):
                    ts = tx.get('time', 0)
                    if ts > last_tx_ts:
                        last_tx_ts = ts
                
                if last_tx_ts < max_ts:
                    return {
                        'address': address,
                        'balance': balance,
                        'last_seen': time.strftime('%Y-%m-%d', time.gmtime(last_tx_ts))
                    }
    except:
        pass
    return None

def main():
    # 2010-2015 Block range
    # 32490 (start of 2010) to 391000 (end of 2015)
    
    found = []
    checked_blocks = set()
    
    print("Starting blockchain search for dormant targets (any balance)...")
    
    while len(found) < 5: # Small test
        h = random.randint(32490, 391000)
        if h in checked_blocks: continue
        checked_blocks.add(h)
        
        print(f"Checking block {h}...")
        addrs = get_block_addresses(h)
        for a in addrs:
            res = check_address(a)
            if res:
                print(f"  [FOUND] {res}")
                found.append(res)
                if len(found) >= 5: break
        
        time.sleep(1) # Be nice

    print(f"Found {len(found)} candidates.")

if __name__ == "__main__":
    main()
