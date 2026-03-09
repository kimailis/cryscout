import json
from collections import Counter

with open('sigs_bc1ql5hl.json', 'r') as f:
    sigs = json.load(f)

print(f"Total sigs: {len(sigs)}")

# Check for R-reuse
r_to_sigs = {}
for sig in sigs:
    r = sig['r']
    if r not in r_to_sigs:
        r_to_sigs[r] = []
    r_to_sigs[r].append(sig)

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

for r, s_list in r_to_sigs.items():
    if len(s_list) > 1:
        print(f"!!! R-REUSE FOUND !!! R: {hex(r)}")
        for i in range(len(s_list)):
            for j in range(i + 1, len(s_list)):
                s1, s2 = s_list[i], s_list[j]
                if s1['s'] != s2['s']:
                    # k = (z1 - z2) * (s1 - s2)^-1
                    k = ((s1['z'] - s2['z']) * pow(s1['s'] - s2['s'], -1, P)) % P
                    # d = (s*k - z) * r^-1
                    d = ((s1['s'] * k - s1['z']) * pow(r, -1, P)) % P
                    print(f"  Key found between index {i} and {j}!")
                    print(f"  Private Key: {hex(d)}")
                    
                    # Verify
                    from lattice_nonce_analyzer import verify_key
                    if verify_key(d, "bc1ql5hlr8ugqlav2ct3p0c5zwvjyarf0afgh6f5v6"):
                        print("  VERIFIED for bc1ql5hl...")
                    else:
                        print("  Verification FAILED.")

# Check for bias
def get_bias(val, bits=8):
    return val & ((1 << bits) - 1)

lsbs = [get_bias(s['r'], 8) for s in sigs]
lsb_counts = Counter(lsbs)
print(f"Top 5 LSBs (8 bits): {lsb_counts.most_common(5)}")
