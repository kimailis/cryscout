import sqlite3

target = "1AV4KGCsvtPZ9tG7hvwgb85wJyFd9xdpFv"

def check_r_distribution(address):
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    cursor.execute('SELECT r_hex FROM signatures WHERE address = ?', (address,))
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        print(f"No signatures for {address}")
        return
    
    print(f"Checking {len(rows)} r-values for {address}...")
    
    r_ints = [int(r[0], 16) for r in rows]
    r_ints.sort()
    
    print(f"  Min R: {hex(r_ints[0])}")
    print(f"  Max R: {hex(r_ints[-1])}")
    print(f"  Median R: {hex(r_ints[len(r_ints)//2])}")
    
    # Check for small R (less than 128 bits)
    small_r = [r for r in r_ints if r < (1 << 128)]
    if small_r:
        print(f"  Found {len(small_r)} small R values (< 128 bits)!")
        for r in small_r[:5]:
            print(f"    {hex(r)}")

if __name__ == "__main__":
    check_r_distribution(target)
