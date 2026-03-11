#!/usr/bin/env python3
import math
import json
import hashlib
import numpy as np
from collections import Counter
from sklearn.cluster import DBSCAN
from vortex_math_analyzer import analyze_vortex_periodicity
from tcg_norm_analyzer import tcg_norm

# Known library fingerprints (centroids/ranges)
KNOWN_LIBRARIES = {
    "Debian OpenSSL (CVE-2008-0166)": {
        "r_bits_mean": 256.0,
        "vortex_purity": 0.5,
        "features": {"small_k": False, "fixed_r": False}
    },
    "Android SecureRandom (2013)": {
        "r_bits_mean": 250.0,
        "vortex_purity": 0.9,
        "features": {"small_k": True}
    },
    "Randstorm (LCG)": {
        "r_bits_mean": 255.0,
        "vortex_purity": 0.95,
        "features": {"lcg": True}
    }
}

def extract_signature_features(sig):
    """
    Extracts a feature vector from a signature for clustering.
    Vector: [r_bits, vortex_purity, tcg_norm_val]
    """
    r_int = int(sig['r_int'])
    s_int = int(sig['s_int'])
    
    r_bits = r_int.bit_length()
    
    # Vortex purity
    _, purity = analyze_vortex_periodicity(hex(r_int)[2:])
    
    # TCG Norm (using default params)
    norm_val = tcg_norm(r_int, s_int)
    # Scale norm_val to a reasonable range or use log
    norm_log = math.log10(norm_val + 1) if norm_val > 0 else 0
    
    return [r_bits, purity, norm_log]

def cluster_signatures(features_list):
    """
    Groups signatures into clusters using DBSCAN.
    features_list: list of [r_bits, purity, norm_log]
    Returns cluster labels.
    """
    if not features_list:
        return []
    
    X = np.array(features_list)
    
    # Normalize features for better clustering
    # r_bits: ~256
    # purity: 0-1
    # norm_log: varies
    
    # Simple standardization
    X_scaled = X.copy()
    X_scaled[:, 0] = (X[:, 0] - 250) / 10.0 # Focus on deviations from 256
    X_scaled[:, 1] = X[:, 1] * 5.0 # Weight purity more
    
    # eps=0.5, min_samples=2 for small clusters
    db = DBSCAN(eps=0.5, min_samples=2).fit(X_scaled)
    return db.labels_

def identify_library(cluster_features):
    """
    Matches cluster characteristics against known library fingerprints.
    """
    mean_r_bits = cluster_features['r_bits_mean']
    mean_purity = cluster_features['vortex_purity']
    
    if mean_purity > 0.95:
        return "High-Entropy PRNG (LCG/Randstorm?)"
    if mean_r_bits < 200:
        return "Weak Entropy (Small K)"
    if mean_purity < 0.3:
        return "Standard/Modern Library"
        
    return "Unknown/Generic Library"

def get_fingerprint_hash(features):
    """Generates a stable hash for a set of features."""
    feat_str = f"{round(features[0], 1)}_{round(features[1], 2)}_{round(features[2], 1)}"
    return hashlib.sha256(feat_str.encode()).hexdigest()
