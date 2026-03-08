import os
import requests
from bs4 import BeautifulSoup
import pandas as pd

def extract_dormant_btc():
    url = "https://bitinfocharts.com/top-100-dormant_7y-bitcoin-addresses.html"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    if os.path.exists("dormant_btc.html"):
        with open("dormant_btc.html", "r", encoding="utf-8") as f:
            html = f.read()
    else:
        print(f"Fetching {url}...")
        response = requests.get(url, headers=headers)
        html = response.text
        with open("dormant_btc.html", "w", encoding="utf-8") as f:
            f.write(html)

    soup = BeautifulSoup(html, 'html.parser')
    extracted_data = []
    table_ids = ['tblOne', 'tblOne2']
    
    for table_id in table_ids:
        table = soup.find('table', id=table_id)
        if not table: continue
            
        rows = table.find_all('tr')[1:]
        for row in rows:
            cols = row.find_all('td')
            if len(cols) < 3: continue
                
            rank = cols[0].get_text(strip=True)
            address_cell = cols[1]
            address_link = address_cell.find('a')
            if not address_link: continue
            address = address_link.get_text(strip=True)
            
            # Extract Label (e.g., wallet name, hack info)
            label = ""
            small_tag = address_cell.find('small')
            if small_tag:
                label = small_tag.get_text(strip=True)
            
            balance_text = cols[2].get_text(separator=" ", strip=True)
            btc_balance = balance_text.split("BTC")[0].strip() + " BTC"
            
            extracted_data.append({
                "Rank": rank,
                "Address": address,
                "Label": label,
                "Balance": btc_balance
            })

    if extracted_data:
        df = pd.DataFrame(extracted_data).head(100)
        df.to_csv("dormant_addresses.csv", index=False)
        print(f"Successfully extracted {len(df)} addresses with labels to dormant_addresses.csv")
    else:
        print("Failed to extract data.")

if __name__ == "__main__":
    extract_dormant_btc()
