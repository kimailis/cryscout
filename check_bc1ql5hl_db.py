import sqlite3

def check():
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    addr = 'bc1ql5hlwf3at7jt96rvmgv8zaf7ls66skshm6669v'
    cur.execute('SELECT r_hex, z_hex, s_hex FROM signatures WHERE address = ?', (addr,))
    rows = cur.fetchall()
    print(f"Found {len(rows)} sigs for {addr}")
    r_map = {}
    for r, z, s in rows:
        if r not in r_map: r_map[r] = []
        r_map[r].append((z, s))
    for r, items in r_map.items():
        if len(items) > 1:
            z_vals = set(it[0] for it in items)
            if len(z_vals) > 1:
                print(f"!!! SOLVABLE REUSE FOUND !!! R: {r}")
    conn.close()

if __name__ == "__main__":
    check()
