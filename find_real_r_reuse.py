import json
import sys
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key

P = SECP256k1.order

def solve_nonce_collision(sigs, address):
    print(f"Checking for hidden nonce collisions (k_i = k_j) in {len(sigs)} signatures...")
    
    # Precompute u_i and t_i such that k_i = u_i + t_i * d
    # s_i * k_i = z_i + r_i * d  =>  k_i = z_i/s_i + (r_i/s_i)*d
    prepared = []
    for i, s in enumerate(sigs):
        try:
            s_inv = pow(s['s'], -1, P)
            u = (s_inv * s['z']) % P
            t = (s_inv * s['r']) % P
            prepared.append({'i': i, 'u': u, 't': t, 'r': s['r']})
        except: continue

    found = 0
    for i in range(len(prepared)):
        for j in range(i + 1, len(prepared)):
            p1, p2 = prepared[i], prepared[j]
            
            # If k1 = k2, then:
            # u1 + t1*d = u2 + t2*d
            # d * (t1 - t2) = u2 - u1
            # d = (u2 - u1) * (t1 - t2)^-1
            
            dt = (p1['t'] - p2['t']) % P
            du = (p2['u'] - p1['u']) % P
            
            if dt == 0:
                if du == 0:
                    # This is a standard R-reuse (if r1=r2) or a very weird case
                    continue
                continue
                
            d = (du * pow(dt, -1, P)) % P
            
            if verify_key(d, address):
                print(f"!!! KEY RECOVERED via Nonce Collision (k_{p1['i']} = k_{p2['j']}) !!!")
                print(f"Address: {address}")
                print(f"Private Key: {hex(d)}")
                found += 1
                return d # Stop after first success
                
    if found == 0:
        print("No nonce collisions found.")
    return None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 find_real_r_reuse.py <sigs.json> <address>")
    else:
        with open(sys.argv[1], "r") as f:
            sigs = json.load(f)
        solve_nonce_collision(sigs, sys.argv[2])
