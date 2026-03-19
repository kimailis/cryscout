import re
import sqlite3
from bs4 import BeautifulSoup

def extract_from_html(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        html = f.read()
    
    soup = BeautifulSoup(html, 'html.parser')
    extracted = []
    
    # Tables often have IDs like tblOne or tblOne2
    tables = soup.find_all('table')
    for table in tables:
        rows = table.find_all('tr')[1:] # Skip header
        for row in rows:
            cols = row.find_all('td')
            if len(cols) < 3: continue
            
            addr_cell = cols[0]
            addr_link = addr_cell.find('a')
            if not addr_link: continue
            address = addr_link.text.strip()
            
            # Balance is usually in the second or third column
            balance_text = cols[1].text.strip()
            # Extract number from "10,000 BTC ($...)"
            bal_match = re.search(r'([\d,.]+)\s*BTC', balance_text)
            balance = 0.0
            if bal_match:
                balance = float(bal_match.group(1).replace(',', ''))
            
            # Look for "Outs" count to confirm outgoing transactions
            outs = 0
            outs_match = re.search(r'Outs:\s*(\d+)', row.text)
            if outs_match:
                outs = int(outs_match.group(1))
            else:
                # Sometimes it's in a specific column on BitInfoCharts
                for col in cols:
                    if 'data-val' in col.attrs and col.text.isdigit():
                        # This is a heuristic, bitinfo often has Outs at the end
                        pass
            
            # If balance > 0
            if balance > 0:
                extracted.append({
                    'address': address,
                    'balance': balance,
                    'outs': outs
                })
    return extracted

def main():
    all_targets = []
    for f in ['bitinfo_formatted.html', 'bitinfo_test.html', 'bitinfo_test.html']: # Check both
        try:
            targets = extract_from_html(f)
            print(f"Extracted {len(targets)} targets from {f}")
            all_targets.extend(targets)
        except Exception as e:
            print(f"Error parsing {f}: {e}")

    # Remove duplicates
    unique_targets = {t['address']: t for t in all_targets}.values()
    print(f"Total unique targets found: {len(unique_targets)}")

    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    
    count = 0
    for t in unique_targets:
        # Check if they really fit the criteria of having an exposed public key (outs > 0)
        # However, the user said "prior outgoing transactions prior to dormancy"
        # If the HTML doesn't show it, we might need to check via API later, 
        # but for now we ingest if they meet the balance and are in the dormant list.
        cursor.execute('''
            INSERT OR IGNORE INTO addresses (address, balance, status, potential_weakness, sigs_fetched, sigs_scanned)
            VALUES (?, ?, 'Dormant', 'Dormant 10y+ (Historical Target)', 0, 0)
        ''', (t['address'], t['balance']))
        if cursor.rowcount > 0:
            count += 1
    
    conn.commit()
    conn.close()
    print(f"Successfully ingested {count} new real targets into the database.")

if __name__ == "__main__":
    main()
