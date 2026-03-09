import hashlib
import base58

def pubkey_to_address(pubkey_hex):
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    
    # 1. SHA-256 on pubkey
    sha256 = hashlib.sha256(pubkey_bytes).digest()
    
    # 2. RIPEMD-160 on result
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    
    # 3. Add version byte (0x00 for Mainnet)
    versioned_payload = b'\x00' + ripemd160
    
    # 4. Double SHA-256 for checksum
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    
    # 5. Base58 check encoding
    address = base58.b58encode(versioned_payload + checksum).decode('ascii')
    return address

def pubkey_to_segwit_address(pubkey_hex):
    # Segwit address (bech32) is more complex, but we can just check if it matches the one we saw
    # For now, let's just check the Legacy one
    pass

if __name__ == "__main__":
    pubkey = "02b00050c089112db90f66e4b755972d5373c6bedabc8b9408f91d7c1ab3dcaae5"
    print(f"Pubkey: {pubkey}")
    print(f"Legacy Address: {pubkey_to_address(pubkey)}")
