#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import time
import re
from db_manager import upsert_address, get_connection
from lattice_nonce_analyzer import pubkey_to_address

def scrape_bitinfo_pages(pages=10):
    """Iterates through multiple pages of dormant addresses."""
    print(f"[Fetcher] Scraping {pages} pages of Dormant BTC Wallets...")
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    total_found = 0
    
    with requests.Session() as session:
        for p in range(1, pages + 1):
            url = f"https://bitinfocharts.com/top-100-dormant_10y-bitcoin-addresses-{p}.html"
            if p == 1: url = "https://bitinfocharts.com/top-100-dormant_10y-bitcoin-addresses.html"
            
            try:
                resp = session.get(url, headers=headers, timeout=10)
                if resp.status_code != 200: break
                
                soup = BeautifulSoup(resp.text, 'html.parser')
                table = soup.find('table', id='table_main') or soup.find('table', class_='bb')
                if not table:
                    # Alternative: find all table rows with 10+ digits address-like strings
                    rows = soup.find_all('tr')
                else:
                    rows = table.find_all('tr')
                
                page_found = 0
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) > 2:
                        addr_text = cols[1].get_text().strip()
                        # Some pages have [wallet: xyz] in same col
                        address = re.sub(r'\[.*?\]', '', addr_text).strip()
                        
                        if not re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', address):
                            continue

                        try:
                            balance_text = cols[2].get_text().split(' ')[0].replace(',', '')
                            balance = float(balance_text)
                        except:
                            continue
                        
                        upsert_address({
                            'address': address,
                            'balance': balance,
                            'current_balance': balance,
                            'status': 'Target',
                            'type': 'Legacy (10y Dormant)',
                            'accessibility': 'Dormant'
                        })
                        page_found += 1
                
                total_found += page_found
                print(f"    Page {p}: Found {page_found} addresses")
                time.sleep(1) # Be gentle to avoid 403
            except Exception as e:
                print(f"    Error page {p}: {e}")
                
    print(f"  [+] Total BitInfo targets imported: {total_found}")

def fetch_historical_p2pk_batch():
    """
    Directly targets known historical 'Satoshi blocks' 
    to extract P2PK Public Keys.
    """
    print("[Fetcher] Fetching surgical Satoshi-era P2PK targets...")
    # List of known block heights with significant dormant P2PK coinbase
    # These are blocks 1000, 1100, 1200... to avoid rate limits while getting variety
    target_heights = [i for i in range(100, 2000, 50)]
    found = 0
    
    for height in target_heights:
        try:
            # Use blockchain.info for raw block (reliable for early blocks)
            url = f"https://blockchain.info/rawblock/{height}?format=json"
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200: continue
            
            block = resp.json()
            cb = block['tx'][0]
            for out in cb['out']:
                script = out.get('script', '')
                if script.startswith('41') and script.endswith('ac'):
                    pubkey = script[2:-2]
                    addr = pubkey_to_address(pubkey)
                    
                    upsert_address({
                        'address': addr,
                        'balance': out['value']/1e8,
                        'current_balance': out['value']/1e8,
                        'status': 'Target',
                        'type': f'P2PK (Block {height})',
                        'accessibility': 'Exposed PubKey'
                    })
                    
                    # Inject PubKey
                    conn = get_connection()
                    c = conn.cursor()
                    c.execute("INSERT OR IGNORE INTO signatures (address, pubkey_hex, is_biased) VALUES (?, ?, 0)", (addr, pubkey))
                    conn.commit()
                    conn.close()
                    found += 1
            
            print(f"    Satoshi Block {height} processed.")
            time.sleep(0.5)
        except: continue
        
    print(f"  [+] Found {found} high-value Satoshi P2PK targets.")

if __name__ == "__main__":
    scrape_bitinfo_pages(5) # Get first 500 dormant rich addresses
    fetch_historical_p2pk_batch() # Get ~40 Satoshi P2PK targets
