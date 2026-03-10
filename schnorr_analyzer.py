#!/usr/bin/env python3
"""
Phase 3.4 — Taproot / Schnorr Signature Analysis

Bitcoin Taproot (BIP340/341) uses Schnorr signatures instead of ECDSA.
The same HNP principle applies: if nonces are biased, we can extract
the private key via lattice reduction.

Schnorr: sig = (R, s) where s = k - e*d (mod N), e = hash(R || P || m)
vs ECDSA: sig = (r, s) where s = k^{-1} * (z + r*d) (mod N)

Key differences:
- Schnorr R is the full x-coordinate of k*G (32 bytes, x-only)
- e is a tagged hash, not just z
- The math for nonce recovery is simpler for Schnorr
"""
import hashlib
import struct
import ecdsa
from ecdsa import SECP256k1
from db_manager import get_connection, add_recovered_key, add_finding, save_signatures
from lattice_nonce_analyzer import verify_key, solve_hnp
from api_client import api

P_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = SECP256k1.generator
N = SECP256k1.order


def tagged_hash(tag, data):
    """BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def parse_schnorr_witness(witness_items):
    """
    Parse a Taproot witness to extract Schnorr signature components.
    
    Taproot key-spend witness: [signature]
    Taproot script-spend witness: [script_args..., script, control_block]
    
    A Schnorr signature is 64 bytes (or 65 with sighash type).
    """
    sigs = []
    for item in witness_items:
        if isinstance(item, str):
            item_bytes = bytes.fromhex(item)
        else:
            item_bytes = item
        
        # Schnorr sig is exactly 64 bytes (default SIGHASH_ALL) or 65 (explicit sighash)
        if len(item_bytes) in [64, 65]:
            r_bytes = item_bytes[:32]
            s_bytes = item_bytes[32:64]
            sighash = item_bytes[64] if len(item_bytes) == 65 else 0x01
            
            r_int = int.from_bytes(r_bytes, 'big')
            s_int = int.from_bytes(s_bytes, 'big')
            
            # Validate: R must be a valid x-coordinate, s must be < N
            if 0 < r_int < P_CURVE and 0 < s_int < N:
                sigs.append({
                    'r': r_int,
                    's': s_int,
                    'r_bytes': r_bytes,
                    's_bytes': s_bytes,
                    'sighash_type': sighash
                })
    
    return sigs


def extract_schnorr_sigs_from_tx(tx_data, target_address=None):
    """Extract Schnorr signatures from a transaction's Taproot inputs."""
    sigs = []
    
    if not tx_data:
        return sigs
    
    for i, vin in enumerate(tx_data.get('vin', [])):
        # Check if this is a Taproot input (witness with Schnorr sig)
        witness = vin.get('witness', [])
        if not witness:
            witness = vin.get('txinwitness', [])
        
        if not witness:
            continue
        
        # Check prevout address type
        prevout = vin.get('prevout', {})
        addr = prevout.get('scriptpubkey_address', '')
        
        if target_address and addr != target_address:
            continue
        
        # Only process bc1p... (Taproot) addresses
        if not addr.startswith('bc1p'):
            continue
        
        schnorr_sigs = parse_schnorr_witness(witness)
        for sig in schnorr_sigs:
            sig['txid'] = tx_data.get('txid', '')
            sig['vin'] = i
            sig['address'] = addr
            # Extract internal public key from scriptPubKey (last 32 bytes of witness program)
            scriptpubkey = prevout.get('scriptpubkey', '')
            if len(scriptpubkey) >= 68:  # OP_1 OP_PUSH32 <32 bytes>
                sig['pubkey_x'] = scriptpubkey[4:]  # x-only pubkey hex
            sigs.append(sig)
    
    return sigs


def schnorr_r_reuse_check(sigs, address):
    """
    Check for R-reuse in Schnorr signatures.
    Same R with different messages → instant key recovery:
    d = (s1 - s2) / (e2 - e1) mod N
    """
    from collections import defaultdict
    r_groups = defaultdict(list)
    
    for sig in sigs:
        r_groups[sig['r']].append(sig)
    
    for r_val, group in r_groups.items():
        if len(group) < 2:
            continue
        
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                s1, s2 = group[i]['s'], group[j]['s']
                # We'd need the challenge hash e for each — which requires the full message
                # For now, flag this as a critical finding
                print(f"  ⚠ SCHNORR R-REUSE DETECTED: R={hex(r_val)[:20]}...")
                print(f"    TX1: {group[i].get('txid', 'unknown')}")
                print(f"    TX2: {group[j].get('txid', 'unknown')}")
                add_finding(address, 'Schnorr R-Reuse',
                           details=f'R={hex(r_val)[:30]}, TXs: {group[i].get("txid","")[:16]}, {group[j].get("txid","")[:16]}',
                           severity='Critical')
                return True
    
    return False


def schnorr_weak_nonce_check(sigs, address):
    """
    Check for weak nonces in Schnorr signatures.
    If k is small, R = k*G will have a small x-coordinate.
    """
    for sig in sigs:
        r = sig['r']
        # Check if R_x is suspiciously small (< 2^200 bits)
        if r.bit_length() < 200:
            print(f"  ⚠ SCHNORR WEAK NONCE: R only {r.bit_length()} bits")
            add_finding(address, 'Schnorr Weak Nonce',
                       details=f'R bit length: {r.bit_length()}, TX: {sig.get("txid","")[:16]}',
                       severity='High')
            return True
    
    return False


def scan_taproot_addresses(max_addresses=50):
    """Scan all bc1p... addresses for Schnorr signature vulnerabilities."""
    print("=" * 60)
    print("TAPROOT / SCHNORR SIGNATURE ANALYSIS")
    print("=" * 60)
    
    conn = get_connection()
    c = conn.cursor()
    
    # Find Taproot addresses
    c.execute("""
        SELECT address, COALESCE(current_balance, balance, 0) as bal, transactions
        FROM addresses
        WHERE address LIKE 'bc1p%'
        ORDER BY bal DESC
        LIMIT ?
    """, (max_addresses,))
    targets = c.fetchall()
    conn.close()
    
    if not targets:
        print("  No Taproot (bc1p...) addresses tracked")
        # Also check for any that could be added
        print("  Tip: Add Taproot addresses to the database for Schnorr analysis")
        return []
    
    print(f"  Found {len(targets)} Taproot addresses")
    
    findings = []
    for addr, bal, tx_count in targets:
        print(f"\n  {addr[:40]}... ({bal} BTC, {tx_count or 0} TXs)")
        
        # Fetch transaction data
        try:
            txids = api.get_address_txids(addr, max_txs=100)
            if not txids:
                print(f"    No spending transactions")
                continue
            
            all_sigs = []
            for txid in txids[:20]:  # Limit API calls
                tx_data = api.get_tx_data(txid)
                if tx_data:
                    sigs = extract_schnorr_sigs_from_tx(tx_data, target_address=addr)
                    all_sigs.extend(sigs)
            
            if not all_sigs:
                print(f"    No Schnorr signatures extracted")
                continue
            
            print(f"    Extracted {len(all_sigs)} Schnorr signatures")
            
            # Run checks
            if schnorr_r_reuse_check(all_sigs, addr):
                findings.append(('R-Reuse', addr))
            
            if schnorr_weak_nonce_check(all_sigs, addr):
                findings.append(('Weak Nonce', addr))
            
            # Apply HNP lattice to Schnorr sigs
            # For Schnorr: s = k - e*d, so s + e*d = k
            # This is the same HNP structure as ECDSA
            if len(all_sigs) >= 4:
                hnp_sigs = []
                for sig in all_sigs:
                    hnp_sigs.append({
                        'r': sig['r'],
                        's': sig['s'],
                        'z': 0,  # Placeholder — would need full challenge hash
                    })
                # Note: Full Schnorr HNP requires the challenge value e
                # which needs the full tx preimage reconstruction for Taproot
                print(f"    {len(hnp_sigs)} sigs available for lattice (needs challenge hash)")
                
        except Exception as e:
            print(f"    Error: {e}")
    
    print(f"\n  Taproot scan complete: {len(findings)} findings")
    return findings


if __name__ == "__main__":
    scan_taproot_addresses()
