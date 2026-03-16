import sqlite3
import hashlib
from ecdsa import SECP256k1, SigningKey

def get_pubkeys():
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT address, pubkey_hex FROM signatures WHERE pubkey_hex IS NOT NULL")
    rows = cur.fetchall()
    conn.close()
    return rows

def check_weak_keys():
    targets = get_pubkeys()
    print(f"Checking {len(targets)} public keys for common weak derivations...")
    
    for addr, pk_hex in targets:
        # Candidates for d
        candidates = []
        
        # 1. d = SHA256(addr)
        candidates.append(int(hashlib.sha256(addr.encode()).hexdigest(), 16))
        
        # 2. d = SHA256(SHA256(addr))
        candidates.append(int(hashlib.sha256(hashlib.sha256(addr.encode()).digest()).hexdigest(), 16))
        
        # 3. d = address interpreted as hex (if valid)
        try:
            # This is rare but possible for some test tools
            pass
        except: pass
        
        # 4. Common words
        for word in ["satoshi", "bitcoin", "genesis", "blockchain", "money", "password", "123456"]:
            candidates.append(int(hashlib.sha256(word.encode()).hexdigest(), 16))
            
        for d in candidates:
            if d <= 0 or d >= SECP256k1.order: continue
            try:
                sk = SigningKey.from_secret_exponent(d, curve=SECP256k1)
                vk = sk.get_verifying_key()
                # Check both compressed and uncompressed
                pk_uncomp = "04" + vk.to_string().hex()
                pk_comp = vk.to_string("compressed").hex()
                
                if pk_uncomp == pk_hex.lower() or pk_comp == pk_hex.lower():
                    print(f"!!! SUCCESS !!! Weak key found for {addr}")
                    print(f"Key: {hex(d)}")
                    return
            except: continue
    print("No simple weak keys found.")

if __name__ == "__main__":
    check_weak_keys()
