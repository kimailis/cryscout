import sqlite3
import ecdsa
from ecdsa import SECP256k1
from ecdsa.numbertheory import inverse_mod, square_root_mod_prime

P = SECP256k1.curve.p()
N = SECP256k1.order
G = SECP256k1.generator

def get_y_from_x(x, is_even):
    # y^2 = x^3 + 7 (mod P)
    y_sq = (pow(x, 3, P) + 7) % P
    y = square_root_mod_prime(y_sq, P)
    if (y % 2 == 0) != is_even:
        y = P - y
    return y

def recover_pubkey(r, s, z):
    # r = (k*G).x
    # s = k^-1 * (z + r*d)
    # k*G = s^-1 * (z*G + r*Q)
    # Q = r^-1 * (s * (k*G) - z*G)
    
    # k*G is a point with x-coordinate r. There are 2 possible y-coordinates.
    s_inv = inverse_mod(s, N)
    r_inv = inverse_mod(r, N)
    
    pubkeys = []
    for is_even in [True, False]:
        try:
            y = get_y_from_x(r, is_even)
            KG = ecdsa.ellipticcurve.Point(SECP256k1.curve, r, y)
            
            # Q = r^-1 * (s * KG - z * G)
            Q = r_inv * (s * KG + (N - z) * G)
            
            # Try both compressed and uncompressed
            pub_uncompressed = b'\x04' + Q.x().to_bytes(32, 'big') + Q.y().to_bytes(32, 'big')
            pub_compressed = (b'\x02' if Q.y() % 2 == 0 else b'\x03') + Q.x().to_bytes(32, 'big')
            
            pubkeys.append(pub_uncompressed.hex())
            pubkeys.append(pub_compressed.hex())
        except:
            pass
    return pubkeys

def extract_for_address(address):
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    cursor.execute('SELECT r_int, s_int, z_int, txid FROM signatures WHERE address = ? LIMIT 1', (address,))
    row = cursor.fetchone()
    if not row:
        print(f"No sigs for {address}")
        return
    
    r, s, z, txid = int(row[0]), int(row[1]), int(row[2]), row[3]
    print(f"Recovering pubkey from TX {txid}...")
    
    candidates = recover_pubkey(r, s, z)
    
    # Verify candidates against address
    import hashlib
    import base58
    
    def addr_from_pub(pub_hex):
        pub_bytes = bytes.fromhex(pub_hex)
        sha = hashlib.sha256(pub_bytes).digest()
        pkh = hashlib.new('ripemd160', sha).digest()
        # Legacy
        vh = b'\x00' + pkh
        check = hashlib.sha256(hashlib.sha256(vh).digest()).digest()[:4]
        return base58.b58encode(vh + check).decode()

    # Bech32 verification
    from lattice_nonce_analyzer import bech32_encode, convertbits
    def bech32_from_pub(pub_hex):
        pub_bytes = bytes.fromhex(pub_hex)
        sha = hashlib.sha256(pub_bytes).digest()
        pkh = hashlib.new('ripemd160', sha).digest()
        return bech32_encode('bc', convertbits(pkh, 8, 5))

    found = None
    for pub in candidates:
        if addr_from_pub(pub) == address or bech32_from_pub(pub) == address:
            found = pub
            break
            
    if found:
        print(f"FOUND PUBKEY: {found}")
        cursor.execute('UPDATE signatures SET pubkey_hex = ? WHERE address = ?', (found, address))
        conn.commit()
        print("Updated database.")
    else:
        print("Could not verify pubkey against address.")
    
    conn.close()

if __name__ == "__main__":
    import sys
    addr = sys.argv[1] if len(sys.argv) > 1 else "1AV4KGCsvtPZ9tG7hvwgb85wJyFd9xdpFv"
    extract_for_address(addr)
