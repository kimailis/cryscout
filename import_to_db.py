import pandas as pd
import re
import sqlite3
from db_manager import init_db, DB_NAME

def clean_btc(val):
    if pd.isna(val) or val == '': return 0.0
    if isinstance(val, (int, float)): return float(val)
    cleaned = re.sub(r'[^0-9.]', '', str(val).replace(',', ''))
    try:
        return float(cleaned)
    except:
        return 0.0

def upsert_address_smart(addr_data):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Check if address already exists and what its status is
    cursor.execute("SELECT status FROM addresses WHERE address = ?", (addr_data['address'],))
    row = cursor.fetchone()
    
    if row:
        current_status = row[0]
        # Don't overwrite Spent/Active with Dormant or Unknown
        if current_status == 'Spent/Active' and addr_data['status'] in ['Dormant', 'Unknown']:
            addr_data['status'] = current_status
            
    columns = list(addr_data.keys())
    placeholders = [':' + col for col in columns]
    
    query = f'''
    INSERT INTO addresses ({", ".join(columns)})
    VALUES ({", ".join(placeholders)})
    ON CONFLICT(address) DO UPDATE SET
    {", ".join([f"{col}=excluded.{col}" for col in columns if col != 'address'])},
    last_updated=CURRENT_TIMESTAMP
    '''
    
    cursor.execute(query, addr_data)
    conn.commit()
    conn.close()

def import_csv_to_db(file_path, default_status=None):
    print(f"Importing {file_path} to database...")
    try:
        df = pd.read_csv(file_path)
        for _, row in df.iterrows():
            addr = row.get('Address') or row.get('address')
            if not addr: continue
            
            addr_data = {
                'address': addr,
                'label': row.get('Label') or row.get('label') or '',
                'rank': row.get('Rank') or row.get('rank'),
                'status': row.get('Status') or row.get('status') or default_status or 'Unknown',
                'type': row.get('Type') or row.get('type') or 'Unknown',
                'balance': clean_btc(row.get('Balance') or row.get('Balance (BTC)') or row.get('Current Balance'))
            }
            addr_data = {k: v for k, v in addr_data.items() if pd.notna(v)}
            upsert_address_smart(addr_data)
        
        print(f"Successfully processed {len(df)} rows from {file_path}.")
    except Exception as e:
        print(f"Error importing CSV {file_path}: {e}")

if __name__ == "__main__":
    init_db()
    # Import dormant first, then master tracking (which is more detailed)
    import_csv_to_db("dormant_addresses.csv", default_status='Dormant')
    import_csv_to_db("master_address_tracking.csv")
