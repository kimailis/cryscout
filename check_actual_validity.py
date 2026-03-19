import sqlite3
import requests
import time

def get_actual_balance(address):
    url = f"https://mempool.space/api/address/{address}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            # chain_stats.funded_txo_sum - chain_stats.spent_txo_sum is in Satoshis
            stats = data.get('chain_stats', {})
            balance_sats = stats.get('funded_txo_sum', 0) - stats.get('spent_txo_sum', 0)
            return balance_sats / 100000000.0
        elif resp.status_code == 429:
            print(f"Rate limited for {address}. Sleeping...")
            time.sleep(10)
            return get_actual_balance(address)
        else:
            print(f"Error {resp.status_code} for {address}")
            return None
    except Exception as e:
        print(f"Request failed for {address}: {e}")
        return None

def check_top_validity():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT address, balance, vulnerability_score FROM addresses WHERE vulnerability_score > 0 ORDER BY vulnerability_score DESC LIMIT 20")
    targets = cursor.fetchall()
    
    print(f"{'Address':<40} | {'DB Balance':<10} | {'Actual Balance':<15} | {'Score':<10} | {'Compliance'}")
    print("-" * 100)
    
    count_2_4 = 0
    count_real = 0
    
    for addr, db_bal, score in targets:
        actual = get_actual_balance(addr)
        if actual is not None:
            count_real += 1
            compliance = "YES" if (2.0 <= actual <= 4.0) else "NO"
            if compliance == "YES": count_2_4 += 1
            print(f"{addr:<40} | {db_bal:<10} | {actual:<15.4f} | {score:<10.2f} | {compliance}")
        else:
            print(f"{addr:<40} | {db_bal:<10} | {'FAILED':<15} | {score:<10.2f} | {'?'}")
        time.sleep(1) # Be nice to API

    print("\nSummary for Top 20 Targets:")
    print(f"Real addresses (found on API): {count_real}")
    print(f"Meeting 2.0-4.0 BTC mandate: {count_2_4}")
    
    conn.close()

if __name__ == "__main__":
    check_top_validity()
