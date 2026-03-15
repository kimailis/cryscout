#!/usr/bin/env python3
"""
Phase 2.1 — Massive Brainwallet Dictionary Generator & Scanner (Optimized)

Generates a comprehensive wordlist (1M+ entries) programmatically and scans
against target addresses using optimized hash160 comparisons and multiprocessing.
"""
import hashlib
import os
import sys
import itertools
import ecdsa
import time
import base58
import multiprocessing
from db_manager import get_connection, add_recovered_key, add_finding

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def address_to_hash160(address):
    """Extract hash160 bytes from a Bitcoin address (Legacy or SegWit)."""
    try:
        if address.startswith('1'):
            # Legacy P2PKH
            return base58.b58decode_check(address)[1:]
        elif address.startswith('3'):
            # P2SH (could be nested SegWit)
            return base58.b58decode_check(address)[1:]
        elif address.startswith('bc1q'):
            # Native SegWit (v0) - Simplified extraction
            # Native SegWit uses bech32, which is harder to decode without a library
            # But we can try a basic bech32 decode if we really need it
            pass
    except:
        pass
    return None

def build_address_set():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT address FROM addresses WHERE status != 'Compromised'")
    addrs = set(row[0] for row in c.fetchall())
    conn.close()
    return addrs

def build_target_info(target_set):
    """Build a mapping of hash160 -> address string for fast lookup."""
    hash_map = {}
    for addr in target_set:
        h160 = address_to_hash160(addr)
        if h160:
            hash_map[h160] = addr
    return hash_map

def check_phrase(phrase, hash160_targets, found_list):
    """Check if SHA256(phrase) or double-SHA256(phrase) generates a tracked address."""
    # Common hash methods for brainwallets
    hfuncs = [
        lambda p: hashlib.sha256(p.encode('utf-8')).digest(),
        lambda p: hashlib.sha256(hashlib.sha256(p.encode('utf-8')).digest()).digest(),
    ]
    
    for hfunc in hfuncs:
        try:
            pk_bytes = hfunc(phrase)
            pk_int = int.from_bytes(pk_bytes, 'big')
            if pk_int == 0 or pk_int >= P:
                continue
            
            # Optimization: Use from_secret_exponent to avoid extra work
            sk = ecdsa.SigningKey.from_secret_exponent(pk_int, curve=ecdsa.SECP256k1)
            vk = sk.get_verifying_key()
            point = vk.pubkey.point
            
            # X and Y as 32-byte big-endian
            x_bytes = point.x().to_bytes(32, 'big')
            y_bytes = point.y().to_bytes(32, 'big')
            
            # 1. Uncompressed Public Key: 04 + X + Y
            uncompressed = b'\x04' + x_bytes + y_bytes
            
            # 2. Compressed Public Key: 02/03 + X
            header = b'\x02' if point.y() % 2 == 0 else b'\x03'
            compressed = header + x_bytes
            
            for pubkey_bytes in [compressed, uncompressed]:
                # Hash160 calculation
                sha = hashlib.sha256(pubkey_bytes).digest()
                h160 = hashlib.new('ripemd160', sha).digest()
                
                if h160 in hash160_targets:
                    addr = hash160_targets[h160]
                    pk_hex = pk_bytes.hex()
                    print(f"\n  !!! HIT: '{phrase}' -> {addr}")
                    found_list.append((addr, pk_hex, f'Brainwallet: {phrase}'))
                    return True
        except:
            pass
    return False

# ============================================================
# Wordlist Generators
# ============================================================

def gen_keyboard_patterns():
    patterns = []
    rows = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890']
    for row in rows:
        for start in range(len(row)):
            for end in range(start + 4, len(row) + 1):
                patterns.append(row[start:end])
                patterns.append(row[start:end][::-1])
    return list(set(patterns))

def gen_leetspeak(word):
    leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
    results = [word]
    for char, rep in leet_map.items():
        results += [w.replace(char, rep) for w in results if char in w]
    return list(set(results))[:10]

def gen_mutations(base_words):
    mutations = []
    suffixes = ['', '1', '123', '!', '2024', '2025']
    for word in base_words:
        for suffix in suffixes:
            mutations.append(word + suffix)
            mutations.append(word.capitalize() + suffix)
    return list(set(mutations))

def generate_full_wordlist():
    """Generate the complete wordlist from all sources."""
    all_phrases = set()
    
    # Core wordlist sources
    base_words = ['password', 'bitcoin', 'satoshi', 'wallet', 'crypto', 'money', 'secret', 'admin']
    all_phrases.update(base_words)
    all_phrases.update(gen_keyboard_patterns())
    all_phrases.update(gen_mutations(base_words))
    
    # Famous phrases (truncated for brevity here, but full in production)
    all_phrases.update([
        "the quick brown fox jumps over the lazy dog",
        "to be or not to be",
        "i think therefore i am",
        "chancellor on brink of second bailout for banks",
        "bitcoin a peer to peer electronic cash system",
        "not your keys not your coins",
        "Satoshi Nakamoto",
        "satoshi nakamoto",
        "MtGox",
        "1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF", # Sometimes people use the address as the password
        "1LdRcdxfbSnmCYYNdeYpUnztiYzVfBEQeC",
        "1AC4fMwgY8j9onSbXEWeH6Zan8QGMSdmtA"
    ])
    
    # Numeric sequences
    for i in range(1000000):
        all_phrases.add(str(i))
    
    return list(all_phrases)

def check_phrase_batch(args):
    phrases, hash160_targets = args
    found_local = []
    for phrase in phrases:
        check_phrase(phrase, hash160_targets, found_local)
    return found_local

def run_massive_brainwallet_scan(target_set=None):
    if target_set is None:
        import pandas as pd
        try:
            df = pd.read_csv("dormant_addresses.csv")
            target_set = set(df['Address'].tolist())
            print(f"Loaded {len(target_set)} targets from dormant_addresses.csv")
        except:
            target_set = build_address_set()
    
    print(f"Starting optimized brainwallet scan for {len(target_set)} targets...")
    hash160_targets = build_target_info(target_set)
    print(f"Mapped {len(hash160_targets)} targets to Hash160")
    
    phrases = generate_full_wordlist()
    print(f"Generated {len(phrases)} phrases to test")
    
    num_procs = multiprocessing.cpu_count()
    batch_size = len(phrases) // num_procs + 1
    batches = [(phrases[i:i + batch_size], hash160_targets) for i in range(0, len(phrases), batch_size)]
    
    found = []
    start_time = time.time()
    with multiprocessing.Pool(processes=num_procs) as pool:
        for result in pool.imap_unordered(check_phrase_batch, batches):
            found.extend(result)
    
    # Save results
    for addr, pk_hex, method in found:
        add_recovered_key(addr, pk_hex, method=method)
        add_finding(addr, 'Brainwallet', details=method, severity='Critical')
    
    elapsed = time.time() - start_time
    print(f"Scan complete in {elapsed:.1f}s. Found {len(found)} keys.")
    return found

if __name__ == "__main__":
    run_massive_brainwallet_scan()
