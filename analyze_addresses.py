import pandas as pd
import requests
import time
import os

def analyze_addresses():
    if not os.path.exists("dormant_addresses.csv"):
        print("Missing dormant_addresses.csv. Run extract_data.py first.")
        return

    df = pd.read_csv("dormant_addresses.csv")
    
    analyzed_data = []
    
    # Simple Blockchain.info API (be mindful of rate limits)
    # URL: https://blockchain.info/rawaddr/{address}
    
    print(f"Analyzing {len(df)} addresses...")
    
    # Analyze only a subset first to ensure it works and avoid long waits
    for index, row in df.iterrows():
        address = row['Address']
        label = row['Label'] if pd.notna(row['Label']) else ""
        print(f"Checking address {index+1}/{len(df)}: {address}")
        
        try:
            # We'll use Blockchain.info API
            response = requests.get(f"https://blockchain.info/rawaddr/{address}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                final_balance = data.get('final_balance', 0) / 100_000_000
                total_received = data.get('total_received', 0) / 100_000_000
                total_sent = data.get('total_sent', 0) / 100_000_000
                n_tx = data.get('n_tx', 0)
                
                # Accessibility/Activity status
                status = "Dormant"
                if total_sent > 0:
                    status = "Spent/Active"
                
                # Heuristic for "Burn" addresses or large hacks
                is_accessible = "Unknown"
                if "MtGox-Hack" in label or "hack" in label.lower():
                    is_accessible = "Likely Stolen/Frozen"
                elif "wallet:" in label:
                    is_accessible = "Likely Known/Exchange"
                elif total_sent == 0 and total_received > 0:
                    is_accessible = "Unspent/Lost Keys?"

                # Address Type
                addr_type = "Legacy (1...)"
                if address.startswith('3'):
                    addr_type = "P2SH (3...)"
                elif address.startswith('bc1'):
                    addr_type = "SegWit (bc1...)"

                analyzed_data.append({
                    "Rank": row['Rank'],
                    "Address": address,
                    "Label": label,
                    "Current Balance": f"{final_balance:.2f} BTC",
                    "Total Received": f"{total_received:.2f} BTC",
                    "Total Sent": f"{total_sent:.2f} BTC",
                    "Transactions": n_tx,
                    "Status": status,
                    "Accessibility": is_accessible,
                    "Type": addr_type
                })
            elif response.status_code == 429:
                print("Rate limit reached. Stopping analysis for now.")
                break
            else:
                print(f"Error fetching data for {address}: HTTP {response.status_code}")
                # Append basic info even if API fails
                analyzed_data.append({
                    "Rank": row['Rank'],
                    "Address": address,
                    "Label": label,
                    "Current Balance": "Error",
                    "Status": "API Error",
                    "Accessibility": "Error"
                })

        except Exception as e:
            print(f"Exception checking {address}: {e}")
            analyzed_data.append({
                    "Rank": row['Rank'],
                    "Address": address,
                    "Label": row.get('Label', ""),
                    "Current Balance": "Exception",
                    "Status": "Error",
                    "Accessibility": "Error"
            })
            
        # Respect API rate limits (Blockchain.info is usually generous for small scale)
        time.sleep(1)

    if analyzed_data:
        analyzed_df = pd.DataFrame(analyzed_data)
        analyzed_df.to_csv("analyzed_addresses.csv", index=False)
        
        # Markdown Report
        md = "# Dead Assets & Wallet Analysis Report\n\n"
        md += "| Rank | Address | Label | Balance | Status | Accessibility | Type |\n"
        md += "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n"
        
        for _, row in analyzed_df.iterrows():
            md += f"| {row['Rank']} | {row['Address']} | {row['Label']} | {row['Current Balance']} | {row['Status']} | {row['Accessibility']} | {row.get('Type', 'N/A')} |\n"
            
        with open("analyzed_report.md", "w", encoding="utf-8") as f:
            f.write(md)
            
        print("Analysis complete. Saved to analyzed_report.md and analyzed_addresses.csv")

if __name__ == "__main__":
    analyze_addresses()
