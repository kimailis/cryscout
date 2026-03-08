import hashlib
import ecdsa
import base58
import pandas as pd
import os

# Bitcoin address generation helper
def phrase_to_address(phrase):
    # 1. SHA256 of the phrase = Private Key
    private_key_bytes = hashlib.sha256(phrase.encode('utf-8')).digest()
    
    # 2. Derive Public Key using ECDSA (SECP256k1)
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    # Uncompressed public key starts with 0x04
    public_key_bytes = b'\x04' + vk.to_string()
    
    # 3. SHA256 of Public Key
    sha256_pub = hashlib.sha256(public_key_bytes).digest()
    
    # 4. RIPEMD-160 of the SHA256 hash
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pub)
    hashed_pub = ripemd160.digest()
    
    # 5. Add Mainnet Prefix (0x00)
    prefixed_pub = b'\x00' + hashed_pub
    
    # 6. Double SHA256 for Checksum
    checksum = hashlib.sha256(hashlib.sha256(prefixed_pub).digest()).digest()[:4]
    
    # 7. Base58 Encode
    address = base58.b58encode(prefixed_pub + checksum).decode('utf-8')
    return address, private_key_bytes.hex()

def run_scanner():
    if not os.path.exists("dormant_addresses.csv"):
        print("Missing dormant_addresses.csv.")
        return

    df = pd.read_csv("dormant_addresses.csv")
    target_addresses = set(df['Address'].tolist())
    
    # Example potential passphrases (Brainwallet hunting)
    # In a real scenario, this would be a dictionary of millions of words/phrases
    test_phrases = [
        "satoshi nakamoto",
        "bitcoin is the future",
        "genesis block",
        "correct horse battery staple",
        "password",
        "12345678",
        "to the moon",
        "hal finney",
        "liberty",
        "cypherpunk"
    ]
    
    print(f"Scanning {len(test_phrases)} phrases against {len(target_addresses)} addresses...")
    
    found = False
    for phrase in test_phrases:
        address, priv_hex = phrase_to_address(phrase)
        if address in target_addresses:
            print(f"!!! MATCH FOUND !!!")
            print(f"Phrase: {phrase}")
            print(f"Address: {address}")
            print(f"Private Key (Hex): {priv_hex}")
            found = True
            
    if not found:
        print("No matches found in the initial test set.")

if __name__ == "__main__":
    run_scanner()
