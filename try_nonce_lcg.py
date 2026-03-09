import json
import sys
from lattice_nonce_analyzer import verify_key

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def solve_quadratic(A, B, C):
    # Ax^2 + Bx + C = 0 (mod P)
    # x = (-B +/- sqrt(B^2 - 4AC)) / 2A
    if A == 0:
        if B == 0: return []
        return [(-C * pow(B, -1, P)) % P]
    
    delta = (B*B - 4*A*C) % P
    # Modulo square root (P is prime and P = 3 (mod 4)?)
    # P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    # P % 4 = 1. So we need Tonelli-Shanks.
    
    def tonelli_shanks(n, p):
        if pow(n, (p - 1) // 2, p) != 1: return None
        s = 0
        q = p - 1
        while q % 2 == 0:
            q //= 2
            s += 1
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
            while temp != 1:
                temp = pow(temp, 2, p)
                i += 1
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

def try_nonce_lcg(filename, address):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    if len(sigs) < 4:
        print("Need at least 4 sigs for LCG analysis.")
        return
    
    print(f"Checking for LCG Nonce Relations in {len(sigs)} sigs...")
    
    for i in range(len(sigs) - 3):
        s = sigs[i:i+4]
        u = []
        t = []
        for sig in s:
            s_inv = pow(sig['s'], -1, P)
            u.append((s_inv * sig['z']) % P)
            t.append((s_inv * sig['r']) % P)
        
        # (k3 - k2)^2 = (k4 - k3) (k2 - k1)
        # k_i = u_i + t_i*d
        # Delta_u_i = u_{i+1} - u_i
        # Delta_t_i = t_{i+1} - t_i
        
        du = [u[1]-u[0], u[2]-u[1], u[3]-u[2]]
        dt = [t[1]-t[0], t[2]-t[1], t[3]-t[2]]
        
        # (du1 + dt1*d)^2 = (du2 + dt2*d) (du0 + dt0*d)
        # du1^2 + 2*du1*dt1*d + dt1^2*d^2 = du2*du0 + (du2*dt0 + du0*dt2)*d + dt2*dt0*d^2
        # (dt1^2 - dt2*dt0)d^2 + (2*du1*dt1 - du2*dt0 - du0*dt2)d + (du1^2 - du2*du0) = 0
        
        A = (dt[1]*dt[1] - dt[2]*dt[0]) % P
        B = (2*du[1]*dt[1] - du[2]*dt[0] - du[0]*dt[2]) % P
        C = (du[1]*du[1] - du[2]*du[0]) % P
        
        roots = solve_quadratic(A, B, C)
        for d in roots:
            if verify_key(d, address):
                print(f"!!! SUCCESS !!! LCG relation found starting at index {i}")
                print(f"Private Key: {hex(d)}")
                return d
    print("No LCG relation found.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 try_nonce_lcg.py <sigs.json> <address>")
    else:
        try_nonce_lcg(sys.argv[1], sys.argv[2])
