import requests
import time

def find_all_spending_txs(address, max_pages=20):
    last_txid = None
    all_spending = []
    for page in range(max_pages):
        url = f"https://mempool.space/api/address/{address}/txs/chain"
        if last_txid:
            url += f"/{last_txid}"
        
        print(f"Checking page {page+1} for {address}...")
        resp = requests.get(url)
        if resp.status_code != 200:
            print(f"Error fetching page: {resp.status_code}")
            break
        
        txs = resp.json()
        if not txs:
            print("No more transactions found.")
            break
            
        for tx in txs:
            for vin in tx.get('vin', []):
                if vin.get('prevout', {}).get('scriptpubkey_address') == address:
                    print(f"FOUND SPENDING TX: {tx['txid']}")
                    all_spending.append(tx['txid'])
                    break # Already found one input in this TX, we'll get others later if needed
            last_txid = tx['txid']
        
        time.sleep(0.5)
    
    return all_spending

import sys

if __name__ == "__main__":
    if len(sys.argv) > 1:
        addr = sys.argv[1]
    else:
        addr = "12ib7dApVFvg82TXKycWBNpN8kFyiAN1dr"
    spending = find_all_spending_txs(addr)
    print(f"Total spending transactions found: {len(spending)}")
