#!/usr/bin/env python3
import math
import json
import hashlib
import numpy as np
from collections import Counter
from sklearn.cluster import DBSCAN

# Known library fingerprints (centroids/ranges)
KNOWN_LIBRARIES = {
    "Debian OpenSSL (CVE-2008-0166)": {
        "r_bits_mean": 256.0,
        "features": {"small_k": False, "fixed_r": False}
    },
    "Android SecureRandom (2013)": {
        "r_bits_mean": 250.0,
        "features": {"small_k": True}
    },
    "Randstorm (LCG)": {
        "r_bits_mean": 255.0,
        "features": {"lcg": True}
    }
}

def extract_signature_features(sig):
    """
    Extracts a feature vector from a signature for clustering.
    Vector: [r_bits, s_bits]
    """
    r_int = int(sig['r_int'])
    s_int = int(sig['s_int'])
    
    r_bits = r_int.bit_length()
    s_bits = s_int.bit_length()
    
    return [r_bits, s_bits]

def cluster_signatures(features_list):
    """
    Groups signatures into clusters using DBSCAN.
    features_list: list of [r_bits, s_bits]
    """
    if len(features_list) < 2:
        return [0] * len(features_list)

    X = np.array(features_list)
    # Scale features
    # r_bits: ~256
    # s_bits: ~256

    # Simple standardization
    X_scaled = X.copy()
    X_scaled[:, 0] = (X[:, 0] - 250) / 10.0 # Focus on deviations from 256
    X_scaled[:, 1] = (X[:, 1] - 250) / 10.0

    # eps=0.5, min_samples=2 for small clusters
    db = DBSCAN(eps=0.5, min_samples=2).fit(X_scaled)
    return db.labels_

def identify_library(cluster_features):
    """
    Matches cluster characteristics against known library fingerprints.
    """
    mean_r_bits = cluster_features.get('r_bits_mean', 256)
    mean_s_bits = cluster_features.get('s_bits_mean', 256)

    if mean_r_bits < 200:
        return "Weak Entropy (Small K)"
    if mean_r_bits == 256 and mean_s_bits == 256:
        return "Standard/Modern Library"

    return "Unknown/Generic Library"

def get_fingerprint_hash(features):
    """Generates a stable hash for a set of features."""
    feat_str = f"{round(features[0], 1)}_{round(features[1], 1)}"
    return hashlib.sha256(feat_str.encode()).hexdigest()
