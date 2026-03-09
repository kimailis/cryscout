import glob
import json
from collections import defaultdict
import re

r_to_addrs = defaultdict(set)

for filename in glob.glob("sigs_*.json"):
    addr_match = re.search(r'sigs_([^_.]+)', filename)
    if not addr_match: continue
    addr_prefix = addr_match.group(1)
    
    try:
        with open(filename, "r") as f:
            data = json.load(f)
            for sig in data:
                r = sig['r']
                r_to_addrs[r].add(addr_prefix)
    except: pass

found = False
for r, addrs in r_to_addrs.items():
    if len(addrs) > 1:
        found = True
        print(f"!!! CROSS-ADDRESS R-COLLISION !!! R: {hex(r)}")
        print(f"    Addresses: {addrs}")

if not found:
    print("No cross-address R-collisions found.")
