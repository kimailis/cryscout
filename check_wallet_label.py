import hashlib
import base58
from ecdsa import SigningKey, SECP256k1

def passphrase_to_address(phrase, compressed=True):
    # Try different hashing methods
    # 1. SHA256 of phrase
    seed = hashlib.sha256(phrase.encode()).digest()
    sk = SigningKey.from_string(seed, curve=SECP256k1)
    vk = sk.get_verifying_key()
    pub = vk.to_string("compressed" if compressed else "uncompressed")
    
    sha256 = hashlib.sha256(pub).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    vh = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(vh).digest()).digest()[:4]
    return base58.b58encode(vh + checksum).decode()

def int_to_address(priv_int, compressed=True):
    sk = SigningKey.from_secret_exponent(priv_int, curve=SECP256k1)
    vk = sk.get_verifying_key()
    pub = vk.to_string("compressed" if compressed else "uncompressed")
    sha256 = hashlib.sha256(pub).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    vh = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(vh).digest()).digest()[:4]
    return base58.b58encode(vh + checksum).decode()

def check():
    target = "1BeouDc6jtHpitvPz3gR3LQnBGb7dKRrtC"
    phrase = "7507428"
    
    print(f"Target: {target}")
    try:
        # As phrase seed
        addr = passphrase_to_address(phrase, True)
        print(f"SHA256 phrase (Comp): {addr}")
        if addr == target: print("!!! MATCH !!!")
        
        # As integer
        addr = int_to_address(int(phrase), True)
        print(f"Integer label (Comp): {addr}")
        if addr == target: print("!!! MATCH !!!")
        
        addr = int_to_address(int(phrase), False)
        print(f"Integer label (Uncomp): {addr}")
        if addr == target: print("!!! MATCH !!!")
    except Exception as e: print(e)

if __name__ == "__main__":
    check()
