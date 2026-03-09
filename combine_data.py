import csv
import os

def read_csv(filename):
    if not os.path.exists(filename):
        return []
    with open(filename, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return list(reader)

def consolidate_data():
    master_data = {}
    
    # 1. Load Analyzed Addresses (Main Data Source)
    analyzed = read_csv('analyzed_addresses.csv')
    for row in analyzed:
        master_data[row['Address']] = row
    
    # 2. Load Dormant Addresses
    dormant = read_csv('dormant_addresses.csv')
    for row in dormant:
        addr = row['Address']
        if addr in master_data:
            master_data[addr]['Balance_dormant'] = row.get('Balance', '')
        else:
            master_data[addr] = row
            master_data[addr]['Balance_dormant'] = row.get('Balance', '')
            
    # 3. Load Checked Nonces
    nonces = read_csv('checked_nonces.csv')
    nonce_addresses = {row['Address'] for row in nonces}
    
    for addr in master_data:
        master_data[addr]['Nonces_Checked'] = str(addr in nonce_addresses)
        # 4. Add Tracking Columns
        if 'Analyzed' not in master_data[addr]:
            master_data[addr]['Analyzed'] = str(addr in nonce_addresses)
        if 'Potential_Weakness' not in master_data[addr]:
            master_data[addr]['Potential_Weakness'] = 'None Identified'
            
    if not master_data:
        print("No data found to consolidate.")
        return

    # Determine all fieldnames
    fieldnames = set()
    for row in master_data.values():
        fieldnames.update(row.keys())
    fieldnames = sorted(list(fieldnames))
    
    # Save the consolidated tracking file
    with open('master_address_tracking.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(master_data.values())
        
    print("Successfully created master_address_tracking.csv")

if __name__ == "__main__":
    consolidate_data()
