import sqlite3
import requests
import time

def parse_der(sig_hex):
    if not sig_hex: return None
    start = sig_hex.find('30')
    if start == -1: return None
    sig_hex = sig_hex[start:]
    
    try:
        data = bytes.fromhex(sig_hex)
        if len(data) < 8 or data[0] != 0x30: return None
        r_len = data[3]
        r_hex = sig_hex[8:8+r_len*2]
        s_marker_idx = 4 + r_len
        if s_marker_idx >= len(data) or data[s_marker_idx] != 0x02: return None
        s_len = data[s_marker_idx + 1]
        s_hex = sig_hex[(s_marker_idx+2)*2 : (s_marker_idx+2+s_len)*2]
        return r_hex, s_hex
    except:
        return None

def fetch_sigs():
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()

    # Priority 1: Real addresses with transactions, excluding simulation vanity patterns
    cursor.execute("""
        SELECT address FROM addresses 
        WHERE transactions > 0 
        AND address NOT LIKE '1Bitcoin%'
        AND (sigs_fetched = 0 OR sigs_fetched IS NULL) 
        ORDER BY balance DESC 
        LIMIT 50
    """)
    addresses = [r[0] for r in cursor.fetchall()]

    if not addresses:
        print("No addresses to fetch.")
        conn.close()
        return

    for addr in addresses:
        print(f"Fetching {addr} from blockchain.info...")
        retries = 3
        while retries > 0:
            try:
                resp = requests.get(f"https://blockchain.com/rawaddr/{addr}?limit=50", timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    found_sigs = 0
                    for tx in data.get('txs', []):
                        for i, inp in enumerate(tx.get('inputs', [])):
                            prev_out = inp.get('prev_out', {})
                            if prev_out.get('addr') == addr:
                                sig_hex = inp.get('script') or (inp.get('witness', '').split(',')[0] if inp.get('witness') else '')
                                res = parse_der(sig_hex)
                                if res:
                                    r_hex, s_hex = res
                                    try:
                                        r_int = str(int(r_hex, 16))
                                        s_int = str(int(s_hex, 16))
                                        cursor.execute('''
                                            INSERT OR IGNORE INTO signatures (address, txid, vin, r_hex, s_hex, r_int, s_int, pubkey_hex)
                                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                        ''', (addr, tx['hash'], i, r_hex, s_hex, r_int, s_int, ""))
                                        found_sigs += 1
                                    except:
                                        continue
                    print(f"  -> Found {found_sigs} sigs.")
                    cursor.execute("UPDATE addresses SET sigs_fetched = 1 WHERE address = ?", (addr,))
                    conn.commit()
                    time.sleep(10) # Heavy delay
                    break
                elif resp.status_code == 429:
                    print("  -> Rate limited (429). Waiting 60s...")
                    time.sleep(60)
                    retries -= 1
                elif resp.status_code == 404:
                    print("  -> Not found (404). Skipping.")
                    cursor.execute("UPDATE addresses SET sigs_fetched = 1 WHERE address = ?", (addr,))
                    conn.commit()
                    break
                else:
                    print(f"  -> Error {resp.status_code}. Retrying...")
                    time.sleep(5)
                    retries -= 1
            except Exception as e:
                print(f"  -> Exception: {e}. Retrying...")
                time.sleep(5)
                retries -= 1
        
        if retries == 0:
            print("  -> Giving up on this address for now.")

    conn.close()

if __name__ == "__main__":
    fetch_sigs()
