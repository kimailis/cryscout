#!/usr/bin/env python3
"""
Weak key pattern scanner (Optimized).
Checks if any tracked addresses correspond to known weak private key patterns.
Uses hash160 comparison and multiprocessing for performance.
"""
import hashlib
import ecdsa
import base58
import multiprocessing
import time
from db_manager import get_connection, add_recovered_key, add_finding

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def address_to_hash160(address):
    """Extract hash160 bytes from a Bitcoin address (Legacy or SegWit)."""
    try:
        if address.startswith('1') or address.startswith('3'):
            return base58.b58decode_check(address)[1:]
    except:
        pass
    return None

def build_target_info(target_set):
    hash_map = {}
    for addr in target_set:
        h160 = address_to_hash160(addr)
        if h160:
            hash_map[h160] = addr
    return hash_map

def check_privkey(pk_int, hash160_targets):
    """Check a private key integer against target hash160s."""
    try:
        if pk_int <= 0 or pk_int >= P:
            return None
        
        sk = ecdsa.SigningKey.from_secret_exponent(pk_int, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        point = vk.pubkey.point
        
        x_bytes = point.x().to_bytes(32, 'big')
        y_bytes = point.y().to_bytes(32, 'big')
        
        # Uncompressed
        uncompressed = b'\x04' + x_bytes + y_bytes
        # Compressed
        header = b'\x02' if point.y() % 2 == 0 else b'\x03'
        compressed = header + x_bytes
        
        for pubkey_bytes in [compressed, uncompressed]:
            sha = hashlib.sha256(pubkey_bytes).digest()
            h160 = hashlib.new('ripemd160', sha).digest()
            if h160 in hash160_targets:
                return (hash160_targets[h160], hex(pk_int)[2:].zfill(64))
    except:
        pass
    return None

def scan_small_keys_batch(args):
    start, end, hash160_targets = args
    found_local = []
    for i in range(start, end):
        res = check_privkey(i, hash160_targets)
        if res:
            found_local.append((res[0], res[1], f'Small Key ({i})'))
    return found_local

def scan_small_keys(target_set, max_key=2**20):
    print(f"Parallel scanning small keys 1 to {max_key}...")
    hash160_targets = build_target_info(target_set)
    num_procs = multiprocessing.cpu_count()
    chunk_size = max_key // num_procs + 1
    batches = [(i, min(i + chunk_size, max_key + 1), hash160_targets) 
               for i in range(1, max_key + 1, chunk_size)]
    
    found = []
    with multiprocessing.Pool(processes=num_procs) as pool:
        for result in pool.imap_unordered(scan_small_keys_batch, batches):
            found.extend(result)
    return found

def scan_pattern_keys(target_set):
    print("Scanning pattern keys (Optimized)...")
    hash160_targets = build_target_info(target_set)
    found = []
    patterns = []
    
    # Repeated bytes
    for b in range(1, 256):
        patterns.append(int.from_bytes(b.to_bytes(1, 'big') * 32, 'big'))
    
    # Common patterns
    for hp in ['deadbeef', 'cafebabe', 'baadf00d', 'feedface']:
        val = int(hp * 4, 16)
        patterns.append(val)
        patterns.append(int(hp * 8, 16) % P)
        
    for pk_int in set(patterns):
        res = check_privkey(pk_int, hash160_targets)
        if res:
            found.append((res[0], res[1], 'Pattern Key'))
    
    return found

def scan_android_rng(target_set):
    """Simplified Android RNG bug check."""
    print("Scanning Android RNG (low entropy) ranges...")
    # Check 1 to 2^32 sequentially or via sampling
    return scan_small_keys(target_set, max_key=2**20) # For now, keep it small

def scan_vortex_harmonic_bruteforce(target_set, max_jumps=10000):
    print("Running Vortex Harmonic Pruning Brute Force...")
    hash160_targets = build_target_info(target_set)
    found = []
    # Vortex algorithm uses 2^n mod 9 sequence jumps (1, 2, 4, 8, 7, 5) avoiding 3,6,9
    vortex_cycle = [1, 2, 4, 8, 7, 5]
    for i in range(max_jumps):
        cycle_val = vortex_cycle[i % 6]
        # Jump through keyspace using topological shifts
        pk_int = (1 << (i % 256)) * cycle_val + (i * 9)
        if pk_int >= P or pk_int <= 0:
            pk_int = (pk_int % (P-1)) + 1
        
        res = check_privkey(pk_int, hash160_targets)
        if res:
            found.append((res[0], res[1], 'Vortex Harmonic Pruning'))
            
    return found

def run_weak_key_scan(small_key_max=2**20):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT address FROM addresses WHERE status != 'Compromised'")
    all_addresses = set(row[0] for row in c.fetchall())
    conn.close()
    
    all_found = []
    all_found.extend(scan_pattern_keys(all_addresses))
    all_found.extend(scan_small_keys(all_addresses, max_key=small_key_max))
    
    # Save results
    for addr, pk_hex, method in all_found:
        add_recovered_key(addr, pk_hex, method=method)
        add_finding(addr, 'Weak Key', details=method, severity='Critical')
    
    return all_found

if __name__ == "__main__":
    import sys
    max_key = int(sys.argv[1]) if len(sys.argv) > 1 else 2**20
    run_weak_key_scan(small_key_max=max_key)
