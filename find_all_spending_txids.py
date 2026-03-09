import requests
import time
import sys

def find_spending_txids(address):
    last_txid = None
    all_spending_txids = []
    print(f"Finding spending txids for {address}...")
    while True:
        url = f"https://mempool.space/api/address/{address}/txs/chain"
        if last_txid:
            url += f"/{last_txid}"
        resp = requests.get(url)
        if resp.status_code != 200: break
        txs = resp.json()
        if not txs: break
        for tx in txs:
            for vin in tx.get('vin', []):
                if vin.get('prevout', {}).get('scriptpubkey_address') == address:
                    all_spending_txids.append(tx['txid'])
                    print(f"Found spending tx: {tx['txid']}")
                    break
            last_txid = tx['txid']
        time.sleep(0.5)
    return all_spending_txids

if __name__ == "__main__":
    addr = sys.argv[1] if len(sys.argv) > 1 else "12ib7dApVFvg82TXKycWBNpN8kFyiAN1dr"
    txids = find_spending_txids(addr)
    print(f"Total spending txs found: {len(txids)}")
    for tid in txids:
        print(tid)
