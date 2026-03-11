#!/usr/bin/env python3
import json
import numpy as np
from db_manager import get_connection, create_cluster, assign_sig_to_cluster
from library_fingerprinter import (
    extract_signature_features, cluster_signatures, 
    identify_library, get_fingerprint_hash
)

def run_clustering():
    """Main logic for clustering all signatures in the database."""
    conn = get_connection()
    cursor = conn.cursor()
    
    print("Fetching all signatures for clustering...")
    cursor.execute("SELECT id, r_int, s_int, address FROM signatures")
    rows = cursor.fetchall()
    
    if not rows:
        print("No signatures found in database.")
        conn.close()
        return

    sig_ids = [row[0] for row in rows]
    signatures = [{'r_int': row[1], 's_int': row[2], 'address': row[3]} for row in rows]
    
    print(f"Extracting features for {len(signatures)} signatures...")
    features_list = [extract_signature_features(sig) for sig in signatures]
    
    print("Grouping into clusters (DBSCAN)...")
    labels = cluster_signatures(features_list)
    
    # Organize by cluster
    clusters = {} # label -> list of sig_indices
    for idx, label in enumerate(labels):
        if label not in clusters:
            clusters[label] = []
        clusters[label].append(idx)
    
    print(f"Found {len(clusters) - (1 if -1 in clusters else 0)} clusters (+ {len(clusters.get(-1, []))} noise signatures)")
    
    for label, indices in clusters.items():
        if label == -1: # Noise
            continue
            
        # Calculate cluster features (centroid)
        cluster_feats = np.mean([features_list[i] for i in indices], axis=0)
        fingerprint = get_fingerprint_hash(cluster_feats)
        
        # Identify probable library
        lib_features = {
            'r_bits_mean': cluster_feats[0],
            'vortex_purity': cluster_feats[1],
            'norm_log_mean': cluster_feats[2]
        }
        lib_name = identify_library(lib_features)
        
        # Unique addresses in this cluster
        unique_addrs = set(signatures[i]['address'] for i in indices)
        
        # Create or update cluster in DB
        cluster_id = create_cluster(
            fingerprint_hash=fingerprint,
            library_name=lib_name,
            features=lib_features
        )
        
        # Update DB for this cluster's stats
        cursor.execute('''
            UPDATE clusters SET 
            total_signatures = ?, 
            total_addresses = ?,
            features_json = ?
            WHERE cluster_id = ?
        ''', (len(indices), len(unique_addrs), json.dumps(lib_features), cluster_id))
        
        # Assign signatures to cluster
        for i in indices:
            assign_sig_to_cluster(sig_ids[i], cluster_id)
            
    conn.commit()
    conn.close()
    print("Clustering complete.")

if __name__ == "__main__":
    run_clustering()
