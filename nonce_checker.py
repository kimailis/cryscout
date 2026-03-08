import pandas as pd
import requests
import time
import os
import re

def check_nonce_reuse():
    if not os.path.exists("analyzed_addresses.csv"):
        print("Missing analyzed_addresses.csv. Run analyze_addresses.py first.")
        return

    df = pd.read_csv("analyzed_addresses.csv")
    
    # Filter for addresses with status 'Spent/Active' and multiple transactions
    active_addresses = df[(df['Status'] == 'Spent/Active') & (df['Transactions'] > 1)]
    
    print(f"Checking {len(active_addresses)} active addresses for nonce (k) reuse...")
    
    for _, row in active_addresses.iterrows():
        address = row['Address']
        print(f"Analyzing history of: {address}")
        
        try:
            # Fetch last transactions (Blockchain.info provides JSON)
            # URL: https://blockchain.info/rawaddr/{address}
            response = requests.get(f"https://blockchain.info/rawaddr/{address}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                txs = data.get('tx', [])
                
                # To check nonce reuse, we need to extract the 'r' value from the signatures
                # in the scriptsig of each transaction input.
                
                nonces = {} # r-value -> list of tx hashes
                
                for tx in txs:
                    tx_hash = tx.get('hash')
                    for input_tx in tx.get('inputs', []):
                        # The scriptsig contains the signature (R, S)
                        scriptsig = input_tx.get('script', '')
                        
                        # DER encoded signatures (standard for BTC)
                        # Format: 30 <length> 02 <r_length> <r> 02 <s_length> <s> 01 (sighash)
                        # Example regex to extract r-value (32-33 bytes): 
                        # Looking for "02" then a byte for length, then the r-value
                        match = re.search(r'30[0-9a-f]{2}02([0-9a-f]{2})([0-9a-f]+)02', scriptsig)
                        if match:
                            r_len_hex = match.group(1)
                            r_len = int(r_len_hex, 16) * 2 # length in hex characters
                            r_value = match.group(2)[:r_len]
                            
                            if r_value in nonces:
                                print(f"!!! COLLISION DETECTED !!!")
                                print(f"Address: {address}")
                                print(f"R-Value: {r_value}")
                                print(f"Transaction 1: {nonces[r_value]}")
                                print(f"Transaction 2: {tx_hash}")
                                # If two different hashes have the same r-value, the k was reused.
                                # The private key can be solved with algebra.
                            else:
                                nonces[r_value] = tx_hash
                
                print(f"Processed {len(txs)} transactions, no reuse found.")
            else:
                print(f"Error fetching data for {address}: {response.status_code}")
        
        except Exception as e:
            print(f"Exception checking {address}: {e}")
            
        time.sleep(1) # Rate limit respect

if __name__ == "__main__":
    check_nonce_reuse()
