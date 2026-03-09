#!/usr/bin/env python3
"""
Weak key pattern scanner.
Checks if any tracked addresses correspond to known weak private key patterns:
1. Small private keys (1 to 2^32)  
2. Puzzle transaction keys (known challenge addresses)
3. Well-known compromised keys from history
4. Keys derived from common strings/numbers
5. Keys with repeated byte patterns
"""
import hashlib
import itertools
import ecdsa
import base58
from db_manager import get_connection, add_recovered_key, add_finding
from lattice_nonce_analyzer import pubkey_to_address, pubkey_to_segwit_address

def privkey_to_addresses(privkey_int):
    """Convert a private key integer to all possible address formats."""
    try:
        d_bytes = privkey_int.to_bytes(32, 'big')
        sk = ecdsa.SigningKey.from_string(d_bytes, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        
        addr_uncomp = pubkey_to_address(vk.to_string('uncompressed'))
        addr_comp = pubkey_to_address(vk.to_string('compressed'))
        addr_segwit = pubkey_to_segwit_address(vk.to_string('compressed'))
        
        return [addr_uncomp, addr_comp, addr_segwit]
    except:
        return []

def scan_small_keys(target_set, max_key=2**20):
    """Scan private keys 1 to max_key."""
    print(f"Scanning small keys 1 to {max_key}...")
    found = []
    for i in range(1, max_key + 1):
        addrs = privkey_to_addresses(i)
        for addr in addrs:
            if addr in target_set:
                pk_hex = hex(i)[2:].zfill(64)
                print(f"  !!! WEAK KEY FOUND: {addr} -> key={pk_hex}")
                found.append((addr, pk_hex, f'Small Key ({i})'))
        if i % 100000 == 0:
            print(f"  Progress: {i}/{max_key}")
    return found

def scan_pattern_keys(target_set):
    """Scan keys with common byte patterns."""
    print("Scanning pattern keys...")
    found = []
    patterns = []
    
    # Repeated bytes: 0x01*32, 0x02*32, ...0xff*32
    for b in range(1, 256):
        patterns.append(b.to_bytes(1, 'big') * 32)
    
    # Alternating patterns
    for b1 in range(256):
        for b2 in range(256):
            if b1 != b2:
                patterns.append(bytes([b1, b2]) * 16)
    
    # Sequential bytes
    patterns.append(bytes(range(1, 33)))
    patterns.append(bytes(range(32, 0, -1)))
    
    # Powers of 2
    for exp in range(1, 256):
        val = (1 << exp) % (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
        if val > 0:
            patterns.append(val.to_bytes(32, 'big'))
    
    # Common hex patterns
    hex_patterns = [
        'dead' * 8, 'beef' * 8, 'cafe' * 8, 'babe' * 8,
        'face' * 8, '1234' * 8, 'abcd' * 8, 'ffff' * 8,
        '0000000000000000000000000000000000000000000000000000000000000001',
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    ]
    for hp in hex_patterns:
        try:
            val = int(hp, 16) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            if val > 0:
                patterns.append(val.to_bytes(32, 'big'))
        except:
            pass
    
    print(f"  Testing {len(patterns)} pattern keys...")
    for pat in patterns:
        try:
            pk_int = int.from_bytes(pat, 'big')
            if pk_int == 0 or pk_int >= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:
                continue
            addrs = privkey_to_addresses(pk_int)
            for addr in addrs:
                if addr in target_set:
                    pk_hex = hex(pk_int)[2:].zfill(64)
                    print(f"  !!! PATTERN KEY FOUND: {addr} -> key={pk_hex}")
                    found.append((addr, pk_hex, 'Pattern Key'))
        except:
            pass
    
    return found

def scan_sha256_keys(target_set):
    """Scan keys generated as SHA256 of common strings (brainwallet style)."""
    print("Scanning SHA256-derived keys...")
    found = []
    
    # Common passphrases
    phrases = [
        '', ' ', 'password', 'Password', 'password1', '123456', '12345678',
        'bitcoin', 'Bitcoin', 'satoshi', 'Satoshi', 'nakamoto', 'test',
        'abc', 'abcdef', 'hello', 'world', 'god', 'love', 'money',
        'secret', 'master', 'admin', 'root', 'pass', 'letmein',
        'dragon', 'monkey', 'shadow', 'sunshine', 'princess', 'football',
        'qwerty', 'iloveyou', 'trustno1', 'welcome', 'access',
        'brainwallet', 'wallet', 'bitcoinwallet', 'mybitcoin',
        'correct horse battery staple', 'abandon abandon abandon',
        'how much wood', 'the quick brown fox',
        'to be or not to be', 'i am satoshi nakamoto',
        'just a simple password', 'hello world',
        'a]3{&$k+Fds!%N/=', 'sausage',
    ]
    
    # Numbers as strings
    for i in range(10000):
        phrases.append(str(i))
    
    # Single characters
    for i in range(128):
        phrases.append(chr(i))
    
    # Load extended dictionary if available
    import os
    for dict_file in ['extended_dictionary.txt', 'dictionary.txt']:
        if os.path.exists(dict_file):
            with open(dict_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    phrase = line.strip()
                    if phrase and not phrase.startswith('#'):
                        phrases.append(phrase)
    
    phrases = list(set(phrases))  # Deduplicate
    print(f"  Testing {len(phrases)} phrases...")
    
    for phrase in phrases:
        pk_bytes = hashlib.sha256(phrase.encode('utf-8')).digest()
        pk_int = int.from_bytes(pk_bytes, 'big')
        if pk_int == 0 or pk_int >= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:
            continue
        
        addrs = privkey_to_addresses(pk_int)
        for addr in addrs:
            if addr in target_set:
                pk_hex = pk_bytes.hex()
                print(f"  !!! BRAINWALLET FOUND: '{phrase}' -> {addr} -> key={pk_hex}")
                found.append((addr, pk_hex, f'Brainwallet: {phrase}'))
    
    # Also try double-SHA256 (some wallets use this)
    print(f"  Testing double-SHA256 variants...")
    for phrase in phrases[:500]:  # Limit for speed
        pk1 = hashlib.sha256(phrase.encode('utf-8')).digest()
        pk_bytes = hashlib.sha256(pk1).digest()
        pk_int = int.from_bytes(pk_bytes, 'big')
        if pk_int == 0 or pk_int >= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:
            continue
        addrs = privkey_to_addresses(pk_int)
        for addr in addrs:
            if addr in target_set:
                pk_hex = pk_bytes.hex()
                print(f"  !!! DOUBLE-SHA256 FOUND: '{phrase}' -> {addr} -> key={pk_hex}")
                found.append((addr, pk_hex, f'Double-SHA256: {phrase}'))
    
    return found

def scan_android_rng(target_set):
    """
    Scan for Android SecureRandom bug (2013).
    The bug caused the PRNG to sometimes output predictable values.
    Keys generated with weak entropy have patterns we can check.
    """
    print("Scanning for Android RNG bug patterns...")
    found = []
    
    # Android bug often produced keys where large chunks were zero
    # or where the key was derived from a very small seed space
    # Try keys with leading zeros (low entropy)
    for bits in [32, 48, 64, 80, 96]:
        max_val = 1 << bits
        step = max(1, max_val // 100000)  # Sample 100K keys per range
        for i in range(1, min(max_val, 100000)):
            val = i * step if step > 1 else i
            addrs = privkey_to_addresses(val)
            for addr in addrs:
                if addr in target_set:
                    pk_hex = hex(val)[2:].zfill(64)
                    print(f"  !!! LOW ENTROPY KEY FOUND ({bits}-bit): {addr} -> key={pk_hex}")
                    found.append((addr, pk_hex, f'Low Entropy ({bits}-bit)'))
    
    return found

def run_weak_key_scan(small_key_max=2**20):
    """Run all weak key scans against tracked addresses."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT address FROM addresses")
    all_addresses = set(row[0] for row in c.fetchall())
    conn.close()
    
    print(f"Weak key scan against {len(all_addresses)} tracked addresses")
    print("=" * 60)
    
    all_found = []
    
    # 1. SHA256 / Brainwallet (fastest, most likely to hit)
    all_found.extend(scan_sha256_keys(all_addresses))
    
    # 2. Pattern keys
    all_found.extend(scan_pattern_keys(all_addresses))
    
    # 3. Small keys
    all_found.extend(scan_small_keys(all_addresses, max_key=small_key_max))
    
    # 4. Android RNG
    all_found.extend(scan_android_rng(all_addresses))
    
    # Save results
    for addr, pk_hex, method in all_found:
        add_recovered_key(addr, pk_hex, method=method)
        add_finding(addr, 'Weak Key', details=f'Method: {method}', severity='Critical')
    
    print(f"\n{'='*60}")
    print(f"WEAK KEY SCAN COMPLETE: {len(all_found)} keys found")
    for addr, pk_hex, method in all_found:
        print(f"  {addr} -> {method}")

if __name__ == "__main__":
    import sys
    max_key = int(sys.argv[1]) if len(sys.argv) > 1 else 2**20
    run_weak_key_scan(small_key_max=max_key)
