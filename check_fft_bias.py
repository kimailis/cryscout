import sqlite3
import collections
import numpy as np
from ecdsa import SECP256k1

def check_fft_bias():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    
    # Target addresses with enough signatures for FFT (> 8)
    cursor.execute('SELECT address, count(*) as cnt FROM signatures GROUP BY address HAVING cnt >= 8')
    targets = cursor.fetchall()
    
    print(f"Analyzing {len(targets)} addresses with FFT...")
    
    results = []
    for addr, cnt in targets:
        # Order by block height and vin
        cursor.execute('SELECT r_int FROM signatures WHERE address = ? ORDER BY block_height, vin', (addr,))
        r_values = [int(row[0]) for row in cursor.fetchall() if row[0]]
        
        if len(r_values) < 8: continue
        
        # 1. Normalize R-values to [0, 1]
        data = np.array(r_values, dtype=float) / float(SECP256k1.order)
        
        # 2. Compute FFT
        fft_res = np.abs(np.fft.fft(data))
        # Skip the DC component (index 0)
        fft_res = fft_res[1:len(fft_res)//2]
        
        if len(fft_res) == 0: continue
        
        # 3. Find max frequency magnitude
        max_idx = np.argmax(fft_res)
        max_val = fft_res[max_idx]
        mean_val = np.mean(fft_res)
        
        score = max_val / mean_val if mean_val > 0 else 0
        
        if score > 3.0: # Strong periodic component
            print(f"  !!! FFT BIAS DETECTED !!! Addr: {addr[:15]}... | Score: {score:.2f} | Sigs: {len(r_values)}")
            results.append((addr, score))
            
    conn.close()
    return results

if __name__ == "__main__":
    check_fft_bias()
