import glob
import json
from collections import defaultdict

all_rs = defaultdict(list)

for filename in glob.glob("sigs_*.json"):
    try:
        with open(filename, "r") as f:
            data = json.load(f)
            for sig in data:
                r = sig['r']
                all_rs[r].append({
                    'file': filename,
                    'txid': sig['txid'],
                    's': sig['s'],
                    'z': sig['z']
                })
    except: pass

print(f"Checked {len(all_rs)} unique R values.")

found_collision = False
for r, sources in all_rs.items():
    if len(sources) > 1:
        found_collision = True
        print(f"\n!!! R-COLLISION FOUND !!! R: {hex(r)}")
        for src in sources:
            print(f"  File: {src['file']} | TX: {src['txid']} | S: {hex(src['s'])} | Z: {hex(src['z'])}")
        
        # Try to recover key if the S values are different
        if len(sources) >= 2:
            P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            s1, s2 = sources[0], sources[1]
            if s1['s'] != s2['s']:
                # Same R, different S
                # k = (z1 - z2) * (s1 - s2)^-1
                k = ((s1['z'] - s2['z']) * pow(s1['s'] - s2['s'], -1, P)) % P
                # d = (s1*k - z1) * r^-1
                d = ((s1['s'] * k - s1['z']) * pow(r, -1, P)) % P
                print(f"  POTENTIAL KEY RECOVERY: {hex(d)}")
                
                # Check which file it matches
                from lattice_nonce_analyzer import verify_key
                # Extract address from file name sigs_<address>.json
                import re
                for src in sources:
                    addr_match = re.search(r'sigs_(.+)\.json', src['file'])
                    if addr_match:
                        addr = addr_match.group(1)
                        if verify_key(d, addr):
                            print(f"  !!! VERIFIED KEY for {addr} !!!")

if not found_collision:
    print("No R-collisions found.")
