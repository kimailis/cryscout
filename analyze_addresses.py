import pandas as pd
import requests
import time
import os

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"})

def get_mempool_data(address):
    try:
        url = f"https://mempool.space/api/address/{address}"
        resp = session.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            stats = data['chain_stats']
            first_date = "Unknown"
            last_date = "Unknown"
            n_tx = stats['tx_count']
            
            if n_tx > 0:
                tx_url = f"https://mempool.space/api/address/{address}/txs"
                tx_resp = session.get(tx_url, timeout=15)
                if tx_resp.status_code == 200:
                    txs = tx_resp.json()
                    if txs:
                        # Mempool returns newest first
                        if 'block_time' in txs[0]['status']:
                            last_date = time.strftime('%Y-%m-%d', time.gmtime(txs[0]['status']['block_time']))
                        
                        # Find the first confirmed tx in this batch
                        confirmed_txs = [tx for tx in txs if tx['status']['confirmed']]
                        if confirmed_txs:
                            if n_tx <= 25:
                                first_date = time.strftime('%Y-%m-%d', time.gmtime(confirmed_txs[-1]['status']['block_time']))
                            else:
                                # For more than 25, we'll mark as Old for now and let BC.info try if not blocked
                                first_date = "Multiple Txs (Old)"
            
            return {
                "balance": (stats['funded_txo_sum'] - stats['spent_txo_sum']) / 100_000_000,
                "received": stats['funded_txo_sum'] / 100_000_000,
                "sent": stats['spent_txo_sum'] / 100_000_000,
                "n_tx": n_tx,
                "first_date": first_date,
                "last_date": last_date,
                "source": "Mempool.space"
            }
        elif resp.status_code == 429:
             print("Mempool rate limit! Waiting 60s...")
             time.sleep(60)
    except Exception as e:
        print(f"Mempool error for {address}: {e}")
    return None

def get_blockchain_info_data(address, offset=0):
    max_retries = 2
    for attempt in range(max_retries):
        try:
            url = f"https://blockchain.info/rawaddr/{address}?offset={offset}&limit=50"
            response = session.get(url, timeout=20)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                # Long wait for 429
                wait_time = 300 if attempt == 0 else 600
                print(f"Blockchain.info rate limit hit. Waiting {wait_time}s before retry/skipping...")
                time.sleep(wait_time)
            else:
                print(f"Blockchain.info error {response.status_code} for {address}")
                break
        except Exception as e:
            print(f"Blockchain.info error for {address}: {e}")
            time.sleep(10)
    return None

def analyze_addresses():
    if not os.path.exists("dormant_addresses.csv"):
        print("Missing dormant_addresses.csv. Run extract_data.py first.")
        return

    df = pd.read_csv("dormant_addresses.csv")
    
    # Load existing data
    if os.path.exists("analyzed_addresses.csv"):
        analyzed_df = pd.read_csv("analyzed_addresses.csv")
        # To skip: any address that has a real date or a final status
        to_skip = set(analyzed_df[~analyzed_df['Status'].isin(['Error', 'API Failure'])]['Address'].tolist())
        # But if it has "Multiple Txs (Old)", we might want to try again if we have time, 
        # but for now let's just skip already completed ones to finish the list.
        # UNLESS the user wants to retry them. Let's just finish the 1000 first.
        analyzed_data = analyzed_df.to_dict('records')
    else:
        to_skip = set()
        analyzed_data = []
    
    print(f"Analyzing {len(df)} addresses (skipping {len(to_skip)} already completed)...")
    final_data_map = {row['Address']: row for row in analyzed_data}

    for index, row in df.iterrows():
        address = row['Address']
        if address in to_skip:
            continue
            
        label = row['Label'] if pd.notna(row['Label']) else ""
        print(f"Checking address {index+1}/{len(df)}: {address}")
        
        result = get_mempool_data(address)
        time.sleep(3) # Small delay after mempool
        
        # If result is from mempool but first_date is "Multiple Txs (Old)" or "Unknown", 
        # try blockchain.info with offset to get the real first date.
        if result and (result['first_date'] == "Multiple Txs (Old)" or result['first_date'] == "Unknown"):
            if result['n_tx'] > 0:
                print(f"  Fetching historical data for {address} (Txs: {result['n_tx']})...")
                offset = max(0, int(result['n_tx']) - 1)
                bc_data = get_blockchain_info_data(address, offset=offset)
                if bc_data and 'tx' in bc_data and bc_data['tx']:
                    first_tx = bc_data['tx'][0]
                    first_time = first_tx.get('time')
                    if first_time:
                        result['first_date'] = time.strftime('%Y-%m-%d', time.gmtime(first_time))
                        result['source'] += " + BC.info-Oldest"
                time.sleep(10) # Longer delay after BC.info to avoid 429

        # Fallback
        if not result:
             # ... rest of fallback logic ...
            bc_data = get_blockchain_info_data(address)
            if bc_data:
                n_tx = bc_data.get('n_tx', 0)
                first_date = "Unknown"
                if n_tx > 0:
                    if n_tx <= 50:
                        first_tx = bc_data['tx'][-1]
                        first_date = time.strftime('%Y-%m-%d', time.gmtime(first_tx['time'])) if 'time' in first_tx else "Unknown"
                    else:
                        bc_data_first = get_blockchain_info_data(address, offset=n_tx-1)
                        if bc_data_first and 'tx' in bc_data_first and bc_data_first['tx']:
                            first_tx = bc_data_first['tx'][0]
                            first_date = time.strftime('%Y-%m-%d', time.gmtime(first_tx['time'])) if 'time' in first_tx else "Unknown"
                
                result = {
                    "balance": bc_data.get('final_balance', 0) / 100_000_000,
                    "received": bc_data.get('total_received', 0) / 100_000_000,
                    "sent": bc_data.get('total_sent', 0) / 100_000_000,
                    "n_tx": n_tx,
                    "first_date": first_date,
                    "last_date": time.strftime('%Y-%m-%d', time.gmtime(bc_data['tx'][0]['time'])) if 'tx' in bc_data and bc_data['tx'] else "Unknown",
                    "source": "Blockchain.info"
                }

        if result:
            # Accessibility/Activity status
            status = "Dormant"
            if result['sent'] > 0:
                status = "Spent/Active"
            
            is_accessible = "Unknown"
            if "MtGox-Hack" in label or "hack" in label.lower():
                is_accessible = "Likely Stolen/Frozen"
            elif "wallet:" in label:
                is_accessible = "Likely Known/Exchange"
            elif result['sent'] == 0 and result['received'] > 0:
                is_accessible = "Unspent/Lost Keys?"

            vulnerability_flag = "None"
            if result['first_date'] != "Unknown" and result['first_date'].startswith("2013"):
                vulnerability_flag = "Potential 2013 RNG Weakness"
                print(f"  *** VULNERABILITY FOUND: {address} ({result['first_date']}) ***")

            addr_type = "Legacy (1...)"
            if address.startswith('3'):
                addr_type = "P2SH (3...)"
            elif address.startswith('bc1'):
                addr_type = "SegWit (bc1...)"

            final_data_map[address] = {
                "Rank": row['Rank'],
                "Address": address,
                "Label": label,
                "Current Balance": f"{result['balance']:.2f} BTC",
                "Total Received": f"{result['received']:.2f} BTC",
                "Total Sent": f"{result['sent']:.2f} BTC",
                "Transactions": result['n_tx'],
                "First Seen": result['first_date'],
                "Last Seen": result['last_date'],
                "Status": status,
                "Accessibility": is_accessible,
                "Type": addr_type,
                "Vulnerability": vulnerability_flag
            }
            time.sleep(2)
        else:
            print(f"Failed to fetch data for {address}")
            if address not in final_data_map:
                final_data_map[address] = {
                    "Rank": row['Rank'],
                    "Address": address,
                    "Label": label,
                    "Current Balance": "Error",
                    "First Seen": "Unknown",
                    "Status": "API Failure"
                }
            time.sleep(5)

        # Save every 5 addresses
        if index % 5 == 0:
            pd.DataFrame(list(final_data_map.values())).to_csv("analyzed_addresses.csv", index=False)

    # Final Save
    analyzed_df = pd.DataFrame(list(final_data_map.values()))
    analyzed_df['Rank'] = pd.to_numeric(analyzed_df['Rank'])
    analyzed_df = analyzed_df.sort_values('Rank')
    analyzed_df.to_csv("analyzed_addresses.csv", index=False)
    
    # Markdown Report
    md = "# Dead Assets & Wallet Analysis Report\n\n"
    md += "| Rank | Address | Label | Balance | First Seen | Status | Vulnerability | Type |\n"
    md += "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n"
    
    for _, row in analyzed_df.head(100).iterrows():
        label = row.get('Label', '')
        if pd.isna(label) or str(label) == 'nan': label = ''
        balance = row.get('Current Balance', 'N/A')
        first_seen = row.get('First Seen', 'N/A')
        status = row.get('Status', 'N/A')
        vulnerability = row.get('Vulnerability', 'None')
        if pd.isna(vulnerability) or str(vulnerability) == 'nan': vulnerability = 'None'
        addr_type = row.get('Type', 'N/A')
        
        md += f"| {row['Rank']} | {row['Address']} | {label} | {balance} | {first_seen} | {status} | {vulnerability} | {addr_type} |\n"
        
    with open("analyzed_report.md", "w", encoding="utf-8") as f:
        f.write(md)
        
    print("Analysis complete. Saved to analyzed_report.md and analyzed_addresses.csv")

if __name__ == "__main__":
    analyze_addresses()
