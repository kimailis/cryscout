import hashlib
import ecdsa
import base58

def privkey_to_address(privkey_hex, compressed=True):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(privkey_hex.replace('0x', '')), curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    
    if compressed:
        prefix = b'\x02' if vk.pubkey.point.y() % 2 == 0 else b'\x03'
        public_key = prefix + vk.to_string()[:32]
    else:
        public_key = b'\x04' + vk.to_string()
        
    sha256 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    
    # P2PKH: 0x00 + ripemd160
    versioned_payload = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    return base58.b58encode(versioned_payload + checksum).decode()

keys = [
    ('1AV4KGCsvtPZ9tG7hvwgb85wJyFd9xdpFv', '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
    ('13kxWCuDWN1gGSe2vPmsSBVXyPfYLMh6M4', '0x5d9b62f559640ed9174092496a0901e85f5243286f05e46ef9f2815b16f81798')
]

for target_addr, priv in keys:
    print(f"\nVerifying {target_addr}...")
    try:
        addr_c = privkey_to_address(priv, compressed=True)
        addr_u = privkey_to_address(priv, compressed=False)
        print(f"  Compressed:   {addr_c}")
        print(f"  Uncompressed: {addr_u}")
        if target_addr in (addr_c, addr_u):
            print(f"  [!!!] MATCH FOUND!")
        else:
            print(f"  [!] NO MATCH.")
    except Exception as e:
        print(f"  Error: {e}")
