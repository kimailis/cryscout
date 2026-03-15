import sqlite3
import collections

target = "1AV4KGCsvtPZ9tG7hvwgb85wJyFd9xdpFv"
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def check_msb_bias(address):
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    cursor.execute('SELECT r_int, s_int, z_int FROM signatures WHERE address = ?', (address,))
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        print(f"No signatures for {address}")
        return
    
    print(f"Checking {len(rows)} signatures for MSB bias in z/s...")
    
    # Check MSB bias on (z/s mod n)
    # If d is small, k ≈ z/s
    msbs = []
    for r_str, s_str, z_str in rows:
        r, s, z = int(r_str), int(s_str), int(z_str)
        val = (z * pow(s, -1, P)) % P
        msbs.append(val >> 248) # Top 8 bits
        
    counts = collections.Counter(msbs)
    most_common = counts.most_common(5)
    print("Most common 8-bit MSBs of (z/s):")
    for val, count in most_common:
        print(f"  Value: {val:02x}, Count: {count}, Ratio: {count/len(rows):.4f}")

if __name__ == "__main__":
    check_msb_bias(target)
