import pandas as pd
import requests
import time
import os

def find_real_targets():
    if not os.path.exists("analyzed_addresses.csv"):
        print("Run analyze_addresses.py first.")
        return
    
    df = pd.read_csv("analyzed_addresses.csv")
    # Status is "Spent/Active"
    active = df[df['Status'] == 'Spent/Active']
    
    print(f"Checking {len(active)} active addresses for real spending sigs...")
    
    real_targets = []
    for addr in active['Address']:
        try:
            url = f"https://mempool.space/api/address/{addr}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                spent_count = data['chain_stats']['spent_txo_count']
                if spent_count >= 2:
                    print(f"REAL TARGET: {addr} | Spent Count: {spent_count}")
                    real_targets.append((addr, spent_count))
            time.sleep(1)
        except: pass
    
    print("\n--- Summary of Real Targets ---")
    for addr, count in real_targets:
        print(f"{addr} | {count}")

if __name__ == "__main__":
    find_real_targets()
