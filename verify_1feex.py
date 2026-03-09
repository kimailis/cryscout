import hashlib
import base58
from ecdsa import SigningKey, SECP256k1

def privkey_to_address(privkey_int, compressed=True):
    sk = SigningKey.from_secret_exponent(privkey_int, curve=SECP256k1)
    vk = sk.get_verifying_key()
    if compressed:
        pubkey = vk.to_string("compressed")
    else:
        pubkey = vk.to_string("uncompressed")
    
    sha256 = hashlib.sha256(pubkey).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    vh = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(vh).digest()).digest()[:4]
    return base58.b58encode(vh + checksum).decode()

def verify():
    addr_target = "1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF"
    addr_1_comp = privkey_to_address(1, True)
    addr_1_uncomp = privkey_to_address(1, False)
    
    print(f"Target: {addr_target}")
    print(f"Priv 1 (Comp): {addr_1_comp}")
    print(f"Priv 1 (Uncomp): {addr_1_uncomp}")

if __name__ == "__main__":
    verify()
