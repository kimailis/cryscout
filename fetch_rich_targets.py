#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import time
import re
from db_manager import upsert_address, get_connection

def fetch_top_richest_simple(pages=300, min_balance=100.0):
    print(f"[Fetcher] Scraping Richest List up to page {pages} (> {min_balance} BTC)...")
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    total_found = 0
    
    with requests.Session() as session:
        for p in range(1, pages + 1):
            url = f"https://bitinfocharts.com/top-100-richest-bitcoin-addresses-{p}.html"
            if p == 1: url = "https://bitinfocharts.com/top-100-richest-bitcoin-addresses.html"
            
            try:
                resp = session.get(url, headers=headers, timeout=15)
                if resp.status_code != 200: 
                    print(f"    [!] Page {p} error {resp.status_code}")
                    break
                
                soup = BeautifulSoup(resp.text, 'html.parser')
                table = soup.find('table', id='table_main') or soup.find('table', class_='bb')
                if not table: continue
                
                rows = table.find_all('tr')[1:]
                page_added = 0
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) < 5: continue
                    
                    try:
                        addr_link = cols[1].find('a')
                        if not addr_link: continue
                        address = addr_link.get_text().strip()
                        if not re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', address): continue
                        
                        balance = float(cols[2].get_text().split(' ')[0].replace(',', ''))
                        if balance < min_balance: continue
                        
                        # Just get them into the DB
                        upsert_address({
                            'address': address,
                            'balance': balance,
                            'current_balance': balance,
                            'status': 'Target',
                            'accessibility': 'Unknown'
                        })
                        page_added += 1
                    except: continue
                
                total_found += page_added
                if p % 10 == 0:
                    print(f"    Progress: Page {p}, Total found so far: {total_found}")
                time.sleep(1)
            except: time.sleep(5)
            
    print(f"  [+] Finished. Total addresses processed: {total_found}")
    return total_found

if __name__ == "__main__":
    fetch_top_richest_simple(pages=300, min_balance=100.0)
