
import sqlite3
import numpy as np

def check_bias(address):
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    cur.execute('SELECT r_int, s_int, z_int FROM signatures WHERE address=?', (address,))
    sigs = cur.fetchall()
    if not sigs:
        print(f"No signatures for {address}")
        return

    n = len(sigs)
    print(f"Analyzing {n} signatures for {address}...")
    
    # Check bit biases for R
    r_vals = [int(s[0]) for s in sigs]
    for i in range(256):
        bits = [(r >> i) & 1 for r in r_vals]
        avg = sum(bits) / n
        if abs(avg - 0.5) > 0.1:
            print(f"  R Bit {i}: {avg:.3f} bias")
            
    # Check modular biases for R
    for m in range(2, 33):
        counts = {}
        for r in r_vals:
            rem = r % m
            counts[rem] = counts.get(rem, 0) + 1
        for rem, count in counts.items():
            prob = count / n
            expected = 1/m
            if prob > expected * 1.5:
                print(f"  R mod {m} == {rem}: {prob:.3f} (expected {expected:.3f})")

if __name__ == "__main__":
    import sys
    addr = sys.argv[1] if len(sys.argv) > 1 else '1BRPq7D9taTj147df4z9hfo6L4XUMJjQnA'
    check_bias(addr)
