import os
import requests
from bs4 import BeautifulSoup
import pandas as pd
import time

def extract_dormant_btc():
    # Use the main list with offset to get more addresses
    # BitInfoCharts uses offset=100, 200, etc.
    base_url = "https://bitinfocharts.com/top-100-dormant_7y-bitcoin-addresses"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    extracted_data = []
    
    for offset in range(0, 1000, 100):
        url = f"{base_url}-{offset // 100 + 1}.html" if offset > 0 else f"{base_url}.html"
        # Actually, BitInfoCharts top lists often use -2, -3 for pages, and each page has 100
        # BUT our previous attempt showed only 19? That's strange. 
        # Let's try to find ALL tables.
        
        print(f"Fetching: {url}...")
        
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code != 200:
                print(f"Failed: {response.status_code}")
                break
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # They might have multiple tables or different IDs
            tables = soup.find_all('table')
            page_items = 0
            
            for table in tables:
                # Check if this looks like a data table
                rows = table.find_all('tr')
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) < 3: continue
                    
                    rank_text = cols[0].get_text(strip=True)
                    if not rank_text or not rank_text[0].isdigit():
                        continue
                    
                    rank = rank_text.rstrip('.')
                    address_cell = cols[1]
                    address_link = address_cell.find('a')
                    if not address_link: continue
                    address = address_link.get_text(strip=True)
                    
                    # Skip if not a valid BTC address (roughly)
                    if not (address.startswith('1') or address.startswith('3') or address.startswith('bc1')):
                        continue

                    label = ""
                    small_tag = address_cell.find('small')
                    if small_tag:
                        label = small_tag.get_text(strip=True)
                    
                    balance_text = cols[2].get_text(separator=" ", strip=True)
                    btc_balance = balance_text.split("BTC")[0].strip()
                    
                    extracted_data.append({
                        "Rank": rank,
                        "Address": address,
                        "Label": label,
                        "Balance": btc_balance + " BTC"
                    })
                    page_items += 1
            
            print(f"Found {page_items} items on this page.")
            if page_items == 0: break
            
            time.sleep(2)
            
        except Exception as e:
            print(f"Error: {e}")
            break

    if extracted_data:
        df = pd.DataFrame(extracted_data)
        df = df.drop_duplicates(subset=['Address'])
        df['Rank_Int'] = pd.to_numeric(df['Rank'], errors='coerce')
        df = df.sort_values('Rank_Int').drop(columns=['Rank_Int'])
        
        df.to_csv("dormant_addresses.csv", index=False)
        print(f"Total extracted: {len(df)}")
    else:
        print("Failed.")

if __name__ == "__main__":
    extract_dormant_btc()
