import sqlite3
import collections

target = "1AV4KGCsvtPZ9tG7hvwgb85wJyFd9xdpFv"

def check_bias(address):
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    cursor.execute('SELECT r_int, s_int, z_int FROM signatures WHERE address = ?', (address,))
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        print(f"No signatures for {address}")
        return
    
    print(f"Checking {len(rows)} signatures for {address}...")
    
    # Check LSB bias on R
    for bits in range(1, 9):
        mod = 1 << bits
        counts = collections.Counter()
        for r_str, s_str, z_str in rows:
            r = int(r_str)
            counts[r % mod] += 1
        
        most_common = counts.most_common(1)[0]
        ratio = most_common[1] / len(rows)
        if ratio > (1.5 / mod):
            print(f"  [LSB R] {bits}-bit bias: val={most_common[0]}, ratio={ratio:.4f} (Expected {1/mod:.4f})")

    # Check LSB bias on S
    for bits in range(1, 9):
        mod = 1 << bits
        counts = collections.Counter()
        for r_str, s_str, z_str in rows:
            s = int(s_str)
            counts[s % mod] += 1
        
        most_common = counts.most_common(1)[0]
        ratio = most_common[1] / len(rows)
        if ratio > (1.5 / mod):
            print(f"  [LSB S] {bits}-bit bias: val={most_common[0]}, ratio={ratio:.4f} (Expected {1/mod:.4f})")

if __name__ == "__main__":
    check_bias(target)
