#!/usr/bin/env python3
"""
CryScout Reverse Entropy Analyzer — Advanced Cryptanalytic Entropy Metrics

This module provides "Reverse Entropy" equations and metrics used to detect
low-entropy PRNG states and non-obvious patterns in ECDSA nonces.
These are used as high-signal features for the Neural Network.
"""

import math
import numpy as np
from collections import Counter

def calculate_shannon_entropy(data):
    """Calculate standard Shannon entropy of a sequence."""
    if not data:
        return 0
    n = len(data)
    counts = Counter(data)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)
    return entropy

def calculate_permutation_entropy(data, order=3, delay=1):
    """
    Calculate Permutation Entropy (PE).
    PE measures the complexity of a time series by analyzing the 
    order relations between values. Low PE indicates a predictable 
    sequence (e.g., LCG or LFSR).
    """
    if len(data) < order:
        return 0
    
    # Extract overlapping sequences of length 'order'
    y = []
    for i in range(len(data) - (order - 1) * delay):
        y.append(data[i:i + order * delay:delay])
    
    # Convert sequences to permutations (ranks)
    perms = []
    for seq in y:
        # Get rank order of elements
        perm = tuple(np.argsort(seq))
        perms.append(perm)
    
    # Calculate Shannon entropy of the permutation distribution
    n_perms = len(perms)
    counts = Counter(perms)
    pe = -sum((c / n_perms) * math.log2(c / n_perms) for c in counts.values() if c > 0)
    
    # Normalize to [0, 1]
    max_pe = math.log2(math.factorial(order))
    return pe / max_pe if max_pe > 0 else 0

def calculate_sample_entropy(data, m=2, r=0.2):
    """
    Calculate Sample Entropy (SampEn).
    SampEn measures the regularity and complexity of a series.
    Lower values indicate more self-similarity and less randomness.
    """
    if len(data) < m + 1:
        return 0
    
    data = np.array(data)
    std = np.std(data)
    if std == 0:
        return 0
    
    # Threshold for similarity
    tolerance = r * std
    
    def count_matches(m_len):
        count = 0
        # Extract all sub-sequences of length m_len
        x = np.array([data[i:i+m_len] for i in range(len(data)-m_len+1)])
        # Compare all pairs (excluding self)
        for i in range(len(x)):
            # Use max-norm distance
            diff = np.abs(x - x[i]).max(axis=1)
            count += np.sum(diff <= tolerance) - 1
        return count

    A = count_matches(m + 1)
    B = count_matches(m)
    
    if A > 0 and B > 0:
        return -math.log(A / B)
    return 0

def calculate_conditional_entropy(data):
    """
    Calculate Conditional Entropy H(X_i | X_{i-1}).
    Measures how much information is needed to describe X_i given X_{i-1}.
    Low conditional entropy indicates a strong state-transition relationship.
    """
    if len(data) < 2:
        return 0
    
    # H(X, Y) = H(Y | X) + H(X) => H(Y | X) = H(X, Y) - H(X)
    pairs = list(zip(data[:-1], data[1:]))
    h_joint = calculate_shannon_entropy(pairs)
    h_x = calculate_shannon_entropy(data[:-1])
    
    return h_joint - h_x

def calculate_negentropy_proxy(data):
    """
    Negentropy measures the distance from normality/randomness.
    We use a proxy based on higher-order moments (Skewness and Kurtosis).
    """
    if len(data) < 4:
        return 0
    
    from scipy.stats import skew, kurtosis
    try:
        s = skew(data)
        k = kurtosis(data)
        # J(y) ≈ 1/12 * skew^2 + 1/48 * kurtosis^2
        return (s**2 / 12) + (k**2 / 48)
    except:
        return 0

def calculate_apen(data, m=2, r=0.2):
    """
    Calculate Approximate Entropy (ApEn).
    Similar to Sample Entropy but includes self-matching.
    """
    if len(data) < m + 1:
        return 0
    
    data = np.array(data)
    std = np.std(data)
    if std == 0:
        return 0
    
    tolerance = r * std
    
    def _phi(m_len):
        x = np.array([data[i:i+m_len] for i in range(len(data)-m_len+1)])
        C = []
        for i in range(len(x)):
            diff = np.abs(x - x[i]).max(axis=1)
            count = np.sum(diff <= tolerance)
            C.append(count / len(x))
        return np.mean(np.log(C))

    try:
        return abs(_phi(m) - _phi(m+1))
    except:
        return 0

def calculate_mse(data, scales=5, m=2, r=0.2):
    """
    Calculate Multiscale Entropy (MSE).
    Calculates Sample Entropy across different time scales.
    """
    if len(data) < 10:
        return [0] * scales
    
    mse_values = []
    for scale in range(1, scales + 1):
        # Coarse-graining
        rescaled_data = [np.mean(data[i:i+scale]) for i in range(0, len(data)-scale+1, scale)]
        if len(rescaled_data) > m + 1:
            mse_values.append(calculate_sample_entropy(rescaled_data, m, r))
        else:
            mse_values.append(0)
    return mse_values

def calculate_spectral_entropy(data):
    """
    Calculate Spectral Entropy using the power spectrum.
    """
    if len(data) < 8:
        return 0
    
    # Compute power spectrum
    psd = np.abs(np.fft.fft(data))**2
    psd = psd[:len(psd)//2] # Real part
    
    psd_sum = np.sum(psd)
    if psd_sum == 0:
        return 0
    
    # Normalize to get a probability distribution
    psd_norm = psd / psd_sum
    
    # Shannon entropy of normalized PSD
    entropy = -sum(p * math.log2(p) for p in psd_norm if p > 0)
    
    # Normalize to [0, 1]
    max_entropy = math.log2(len(psd_norm))
    return float(entropy / max_entropy) if max_entropy > 0 else 0

def calculate_renyi_entropy(data, alpha=2):
    """
    Calculate Renyi Entropy of order alpha.
    alpha=2 is Collision Entropy.
    """
    if not data:
        return 0
    n = len(data)
    counts = Counter(data)
    probs = [c / n for c in counts.values()]
    
    if alpha == 1:
        return calculate_shannon_entropy(data)
    
    sum_p_alpha = sum(p**alpha for p in probs)
    if sum_p_alpha <= 0:
        return 0
    
    try:
        entropy = (1 / (1 - alpha)) * math.log2(sum_p_alpha)
        return float(entropy)
    except:
        return 0

def calculate_kl_divergence(data, bins=32):
    """
    Calculate Kullback-Leibler Divergence vs Uniform Distribution.
    Measures how much the distribution deviates from expected randomness.
    """
    if not data or len(data) < bins:
        return 0
    
    # Create histogram
    counts, _ = np.histogram(data, bins=bins)
    n = len(data)
    
    # Observed distribution
    p = counts / n
    # Expected uniform distribution
    q = np.ones(bins) / bins
    
    # Add epsilon to avoid log(0)
    eps = 1e-10
    p = p + eps
    q = q + eps
    p = p / np.sum(p)
    q = q / np.sum(q)
    
    # KL Divergence: D_KL(P || Q) = sum(P(i) * log(P(i) / Q(i)))
    kl = np.sum(p * np.log2(p / q))
    return float(max(0, kl))

def get_reverse_entropy_features(r_values):
    """
    Extract comprehensive reverse-entropy feature set.
    Inputs: r_values (list of ints)
    Returns: list of 32 features
    """
    if len(r_values) < 4:
        return [0.0] * 32
    
    features = []
    
    # Normalize R-values for some metrics
    # Use log2 of R values to capture magnitude distribution
    r_logs = [math.log2(max(1, r)) for r in r_values]
    r_floats = [float(r % (1 << 64)) for r in r_values] # Focus on bottom 64 bits
    
    # 1. Permutation Entropy (orders 3, 4, 5) - 3 features
    features.append(calculate_permutation_entropy(r_floats, order=3))
    features.append(calculate_permutation_entropy(r_floats, order=4))
    features.append(calculate_permutation_entropy(r_floats, order=5))
    
    # 2. Sample & Approx Entropy - 3 features
    features.append(min(calculate_sample_entropy(r_floats, m=2, r=0.2), 5.0) / 5.0)
    features.append(min(calculate_apen(r_floats, m=2, r=0.2), 5.0) / 5.0)
    features.append(min(calculate_sample_entropy(r_logs, m=2, r=0.1), 5.0) / 5.0)
    
    # 3. Multiscale Entropy (first 3 scales) - 3 features
    mse = calculate_mse(r_floats, scales=3)
    features.extend([min(m, 5.0) / 5.0 for m in mse])
    
    # 4. Conditional Entropy (per-byte) - 4 features
    for byte_pos in [0, 1, 30, 31]: # Focus on LSB and MSB bytes
        bytes_seq = [(r >> (byte_pos * 8)) & 0xFF for r in r_values]
        features.append(calculate_conditional_entropy(bytes_seq) / 8.0)
    
    # 5. Spectral Entropy - 2 features
    features.append(calculate_spectral_entropy(r_floats))
    features.append(calculate_spectral_entropy(r_logs))
    
    # 6. Renyi Entropy (Collision Entropy alpha=2) - 2 features
    features.append(calculate_renyi_entropy(r_floats, alpha=2) / 64.0)
    lsb_byte = [r & 0xFF for r in r_values]
    features.append(calculate_renyi_entropy(lsb_byte, alpha=2) / 8.0)
    
    # 7. Negentropy proxy (on bit-lengths) - 1 feature
    bls = [float(r.bit_length()) for r in r_values]
    features.append(min(calculate_negentropy_proxy(bls), 1.0))
    
    # 8. Gap Entropy (entropy of distances between sorted R-values) - 1 feature
    sorted_r = sorted(r_values)
    gaps = [math.log2(max(1, sorted_r[i] - sorted_r[i-1])) for i in range(1, len(sorted_r))]
    features.append(calculate_shannon_entropy(gaps) / 64.0)
    
    # 9. Lempel-Ziv Complexity (on bitstream) - 2 features
    lsb_stream = "".join([str(r & 1) for r in r_values])
    msb_stream = "".join([str((r >> 255) & 1) for r in r_values])
    
    def lz_complexity(s):
        i, l = 1, len(s)
        if l == 0: return 0
        v = {s[0]}
        while i < l:
            j = i + 1
            while j < l and s[i:j] in v:
                j += 1
            v.add(s[i:j])
            i = j
        return len(v)
    
    features.append(min(lz_complexity(lsb_stream) / len(r_values), 1.0) if len(r_values) > 0 else 0)
    features.append(min(lz_complexity(msb_stream) / len(r_values), 1.0) if len(r_values) > 0 else 0)
    
    # 10. Bit-wise Autocorrelation - 4 features
    for lag in [1, 2, 4, 8]:
        if len(lsb_stream) > lag:
            matches = sum(1 for i in range(len(lsb_stream)-lag) if lsb_stream[i] == lsb_stream[i+lag])
            features.append(matches / (len(lsb_stream)-lag))
        else:
            features.append(0.5)
    
    # 11. KL Divergence vs Uniform - 2 features
    features.append(min(calculate_kl_divergence(r_floats) / 5.0, 1.0))
    features.append(min(calculate_kl_divergence(r_logs) / 5.0, 1.0))
    
    # Final check for NaN/Inf
    clean_features = []
    for f in features:
        if math.isnan(f) or math.isinf(f):
            clean_features.append(0.0)
        else:
            clean_features.append(float(f))
            
    # Fill remaining to 32
    clean_features.extend([0.0] * (32 - len(clean_features)))
    return clean_features[:32]



if __name__ == "__main__":
    # Test with random vs biased
    import random
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    print("Testing Reverse Entropy Metrics:")
    
    rand_r = [random.randint(1, P-1) for _ in range(50)]
    rand_feats = get_reverse_entropy_features(rand_r)
    print(f"  Random R-values: Avg Feature Val = {sum(rand_feats)/len(rand_feats):.4f}")
    
    # LCG biased
    lcg_r = []
    k = random.randint(1, P-1)
    a, b = 1103515245, 12345
    for _ in range(50):
        lcg_r.append(k % P)
        k = (a * k + b) % P
    lcg_feats = get_reverse_entropy_features(lcg_r)
    print(f"  LCG Biased R-values: Avg Feature Val = {sum(lcg_feats)/len(lcg_feats):.4f}")
    
    # Permutation entropy specifically
    pe_rand = calculate_permutation_entropy([float(r % (1<<64)) for r in rand_r])
    pe_lcg = calculate_permutation_entropy([float(r % (1<<64)) for r in lcg_r])
    print(f"  PE (Random): {pe_rand:.4f}")
    print(f"  PE (LCG):    {pe_lcg:.4f}")
