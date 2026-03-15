import sqlite3
import collections
import ecdsa
from ecdsa import SECP256k1
from ecdsa.numbertheory import inverse_mod

N = SECP256k1.order
G = SECP256k1.generator
P_prime = SECP256k1.curve.p()

def scan_cross_tx_relations(address, max_sigs=500):
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    cursor.execute('SELECT r_int, s_int, z_int, pubkey_hex, txid FROM signatures WHERE address = ? AND pubkey_hex IS NOT NULL AND pubkey_hex != "" LIMIT ?', (address, max_sigs))
    rows = cursor.fetchall()
    conn.close()
    
    if len(rows) < 2:
        print(f"Not enough sigs with pubkeys for {address}")
        return
    
    pub_hex = rows[0][3]
    pub_bytes = bytes.fromhex(pub_hex)
    if pub_hex.startswith('04'):
        vk = ecdsa.VerifyingKey.from_string(pub_bytes[1:], curve=SECP256k1)
    else:
        vk = ecdsa.VerifyingKey.from_string(pub_bytes, curve=SECP256k1)
    Q = vk.pubkey.point
    
    sigs = []
    for r, s, z, _, txid in rows:
        sigs.append({'r': int(r), 's': int(s), 'z': int(z), 'txid': txid})
        
    print(f"Scanning {len(sigs)} sigs for Cross-TX Relations for {address}...")
    
    # Pre-calculate P_i = k_i*G = s_i^-1 * (z_i*G + r_i*Q)
    points = []
    for i, sig in enumerate(sigs):
        s_inv = inverse_mod(sig['s'], N)
        point = s_inv * (sig['z'] * G + sig['r'] * Q)
        points.append(point)

    point_map = collections.defaultdict(list)
    for i, p in enumerate(points):
        point_map[p.x()].append((i, p))

    # 1. Check for Additive Delta (k_i = k_j + delta)
    print("  Checking for Additive Delta (range 1000)...")
    for delta in range(1, 1001):
        dg = delta * G
        neg_dg = ecdsa.ellipticcurve.Point(SECP256k1.curve, dg.x(), P_prime - dg.y())
        
        for i in range(len(points)):
            # target = points[i] - delta*G
            target = points[i] + neg_dg
            tx = target.x()
            if tx in point_map:
                for j, pj in point_map[tx]:
                    if i != j and pj == target:
                        print(f"!!! SUCCESS !!! Additive delta found: k_{i} = k_{j} + {delta}")
                        # (Omitted recovery logic for brevity, can be added later)
                        return True

    # 2. Check for Multiplicative Relation (k_i = c * k_j)
    print("  Checking for Multiplicative Relation (range 1000)...")
    for c in range(2, 1001):
        for i in range(len(points)):
            # target = c * points[i]
            target = c * points[i]
            tx = target.x()
            if tx in point_map:
                for j, pj in point_map[tx]:
                    if i != j and pj == target:
                        print(f"!!! SUCCESS !!! Multiplicative relation found: k_{j} = {c} * k_{i}")
                        return True
                        
    print("No Cross-TX relations found.")
    return False

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "1AV4KGCsvtPZ9tG7hvwgb85wJyFd9xdpFv"
    scan_cross_tx_relations(target)
