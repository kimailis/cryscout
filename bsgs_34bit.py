import ecdsa
import sqlite3
import time
import binascii
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point

P = SECP256k1.order
curve = SECP256k1.curve
G = SECP256k1.generator

def point_add(p1, p2):
    return p1 + p2

def get_pubkeys():
    conn = sqlite3.connect('cryscout.db')
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT address, pubkey_hex FROM signatures WHERE pubkey_hex IS NOT NULL")
    rows = cur.fetchall()
    conn.close()
    
    pubkeys = []
    for addr, pk_hex in rows:
        try:
            pk_bytes = bytes.fromhex(pk_hex)
            if len(pk_bytes) == 65 and pk_bytes[0] == 0x04:
                x = int.from_bytes(pk_bytes[1:33], 'big')
                y = int.from_bytes(pk_bytes[33:65], 'big')
                pubkeys.append((addr, Point(curve, x, y)))
            elif len(pk_bytes) == 33 and pk_bytes[0] in (0x02, 0x03):
                from ecdsa import VerifyingKey
                vk = VerifyingKey.from_string(pk_bytes, curve=SECP256k1)
                pubkeys.append((addr, vk.pubkey.point))
        except:
            continue
    return pubkeys

def run_bsgs():
    print("Loading public keys...")
    targets = get_pubkeys()
    print(f"Loaded {len(targets)} valid public keys.")
    
    # 2^34 search space
    M = 1 << 17 
    
    print(f"Generating baby steps table (size {M})...")
    t0 = time.time()
    baby_steps = {}
    current = ecdsa.ellipticcurve.INFINITY # Point at infinity
    
    for i in range(M):
        if current.x() is not None:
            baby_steps[current.x()] = i
        current = current + G
    
    print(f"Table generated in {time.time() - t0:.2f}s")
    
    mG = current # This is M * G
    neg_mG = Point(curve, mG.x(), curve.p() - mG.y()) # -M * G
    
    print(f"Starting giant steps for {len(targets)} targets...")
    for idx, (addr, Q) in enumerate(targets):
        current_Q = Q
        found = False
        for j in range(M):
            x = current_Q.x()
            if x in baby_steps:
                i = baby_steps[x]
                # Check if it's i*G or -i*G
                # If i*G == current_Q => Q - j*mG == i*G => Q == j*mG + i*G
                # If -i*G == current_Q => Q - j*mG == -i*G => Q == j*mG - i*G
                # We need to re-verify to be sure
                for possible_d in [j * M + i, j * M - i]:
                    if possible_d > 0 and possible_d * G == Q:
                        print(f"\n!!! SUCCESS !!!")
                        print(f"Address: {addr}")
                        print(f"Private Key: {hex(possible_d)}")
                        with open("keys_recovered.txt", "a") as f:
                            f.write(f"{addr}:{hex(possible_d)}\n")
                        found = True
                        break
            if found: break
            current_Q = current_Q + neg_mG
            
        if (idx + 1) % 50 == 0:
            print(f"  Processed {idx + 1}/{len(targets)}")

if __name__ == "__main__":
    run_bsgs()
