import hashlib
import base58

def pubkey_to_address(pubkey_bytes):
    sha256 = hashlib.sha256(pubkey_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    vh = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(vh).digest()).digest()[:4]
    return base58.b58encode(vh + checksum).decode()

def check_unspendable():
    # 0x00 key
    addr_00 = pubkey_to_address(bytes.fromhex('00'))
    print(f"Address for 0x00: {addr_00}")
    
    # 0x00...00 (65 bytes zero)
    addr_zeros = pubkey_to_address(bytes([0]*65))
    print(f"Address for 65 zeros: {addr_zeros}")
    
    # 0x00...00 (33 bytes zero)
    addr_zeros_33 = pubkey_to_address(bytes([0]*33))
    print(f"Address for 33 zeros: {addr_zeros_33}")

if __name__ == "__main__":
    check_unspendable()
