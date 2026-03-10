#!/usr/bin/env python3
"""
Phase 3.1 — Neural Network Nonce Anomaly Detector

Uses a PyTorch binary classifier trained on synthetic data to detect
hidden patterns in ECDSA nonce (R-value) distributions that statistical
tests might miss.

Architecture:
  Input Features (per signature set):
  ├── R-value bit distribution (256 features)
  ├── R-value byte entropy (32 features)
  ├── LSB pattern vector (16 features)
  ├── MSB pattern vector (16 features)
  ├── Inter-signature R deltas (32 features)
  ├── R-value modular residues mod 2,3,5,7,11,13 (6 features)
  ├── Autocorrelation coefficients (16 features)
  └── Frequency domain (FFT magnitude) (32 features)

  Model: Binary Classifier → P(vulnerable)
"""
import os
import json
import math
import hashlib
import random
import struct
import time

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

from db_manager import get_connection, add_finding
from reverse_entropy_analyzer import get_reverse_entropy_features

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
FEATURE_DIM = 438  # 406 original + 32 reverse entropy
MODEL_PATH = 'nonce_anomaly_model.pt'


# ============================================================
# Feature Extraction
# ============================================================

def extract_features(r_values):
    """Extract a fixed-size feature vector from a list of R-values (ints)."""
    if len(r_values) < 2:
        return None

    features = []

    # 1. Bit distribution (256 features): fraction of R-values with bit i set
    bit_counts = [0] * 256
    for r in r_values:
        for bit in range(256):
            if (r >> bit) & 1:
                bit_counts[bit] += 1
    n = len(r_values)
    features.extend([c / n for c in bit_counts])

    # 2. Byte entropy (32 features): Shannon entropy of each byte position
    for byte_pos in range(32):
        byte_vals = [(r >> (byte_pos * 8)) & 0xFF for r in r_values]
        from collections import Counter
        counts = Counter(byte_vals)
        entropy = -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)
        features.append(entropy / 8.0)  # Normalize to [0, 1]

    # 3. LSB pattern vector (16 features): distribution of R mod 2^k for k=1..16
    for k in range(1, 17):
        mod = 1 << k
        residues = [r % mod for r in r_values]
        counts = Counter(residues)
        most_common_ratio = counts.most_common(1)[0][1] / n
        features.append(most_common_ratio)

    # 4. MSB pattern vector (16 features): bit-length distribution
    bit_lengths = [r.bit_length() for r in r_values]
    bl_counts = Counter(bit_lengths)
    for target_bl in range(241, 257):
        features.append(bl_counts.get(target_bl, 0) / n)

    # 5. Inter-signature R deltas (32 features): statistics of consecutive differences
    deltas = []
    sorted_r = sorted(r_values)
    for i in range(1, len(sorted_r)):
        delta = sorted_r[i] - sorted_r[i - 1]
        deltas.append(delta)

    if deltas:
        delta_bits = [d.bit_length() for d in deltas]
        delta_bl_counts = Counter(delta_bits)
        for target in range(224, 256):
            features.append(delta_bl_counts.get(target, 0) / len(deltas))
    else:
        features.extend([0] * 32)

    # 6. Modular residues (6 features): R mod small primes
    for prime in [2, 3, 5, 7, 11, 13]:
        residues = [r % prime for r in r_values]
        counts = Counter(residues)
        # Chi-squared statistic vs uniform
        expected = n / prime
        chi2 = sum((counts.get(i, 0) - expected) ** 2 / expected for i in range(prime))
        features.append(min(chi2 / 100.0, 1.0))  # Normalize

    # 7. Autocorrelation (16 features): correlation of R[i] with R[i+lag]
    r_normalized = [(r - sum(r_values) / n) for r in r_values]
    var = sum(x * x for x in r_normalized) / n if n > 0 else 1
    for lag in range(1, 17):
        if lag < len(r_normalized) and var > 0:
            autocorr = sum(r_normalized[i] * r_normalized[i + lag]
                           for i in range(len(r_normalized) - lag)) / (n * var)
            features.append(max(-1, min(1, float(autocorr))))
        else:
            features.append(0.0)

    # 8. FFT magnitude (32 features): frequency domain analysis
    if len(r_values) >= 4:
        # Use bit-lengths as a simpler signal for FFT
        signal = [float(r.bit_length()) for r in r_values[:256]]
        # Pad to power of 2
        pad_len = 1
        while pad_len < len(signal):
            pad_len *= 2
        signal.extend([0.0] * (pad_len - len(signal)))

        # Manual DFT for first 32 frequency bins
        N = len(signal)
        for k in range(32):
            real = sum(signal[n_] * math.cos(2 * math.pi * k * n_ / N) for n_ in range(N))
            imag = sum(signal[n_] * math.sin(2 * math.pi * k * n_ / N) for n_ in range(N))
            mag = math.sqrt(real * real + imag * imag) / N
            features.append(min(mag / 10.0, 1.0))
    else:
        features.extend([0.0] * 32)
    
    # 9. Reverse Entropy Features (32 features)
    rev_entropy_feats = get_reverse_entropy_features(r_values)
    features.extend(rev_entropy_feats)

    # Pad/truncate to FEATURE_DIM
    features = features[:FEATURE_DIM]
    features.extend([0.0] * (FEATURE_DIM - len(features)))

    return features


# ============================================================
# Synthetic Data Generation
# ============================================================

def generate_random_r_values(count):
    """Generate cryptographically random R-values (SECURE nonces → label 0)."""
    return [random.randint(1, P - 1) for _ in range(count)]


def generate_biased_r_values(count, bias_type='lsb'):
    """Generate biased R-values (WEAK nonces → label 1)."""
    values = []
    if bias_type == 'lcg':
        # LCG nonce: k_{i+1} = a*k_i + b mod P
        a = random.randint(1, P - 1)
        b = random.randint(1, P - 1)
        k = random.randint(1, P - 1)
        for _ in range(count):
            values.append(k % P)
            k = (a * k + b) % P
        return values
    
    if bias_type == 'lfsr':
        # LFSR-like behavior (linear recurrence over GF(2))
        # Simplified: just a shift and xor
        state = random.randint(1, (1 << 256) - 1)
        for _ in range(count):
            values.append(state % P)
            # Feedback: xor bits 0, 2, 3, 5
            fb = (state ^ (state >> 2) ^ (state >> 3) ^ (state >> 5)) & 1
            state = (state >> 1) | (fb << 255)
        return values

    for _ in range(count):
        if bias_type == 'lsb':
            # LSB bias: bottom 8 bits always the same
            r = random.randint(1, P - 1)
            r = (r & ~0xFF) | 0x42
            values.append(r)
        elif bias_type == 'small':
            # Small nonce: only 128 bits of entropy
            r = random.randint(1, 1 << 128)
            values.append(r)
        elif bias_type == 'repeated':
            # Some repeated R values
            base_r = random.randint(1, P - 1)
            if random.random() < 0.3:
                values.append(base_r)
            else:
                values.append(random.randint(1, P - 1))
        elif bias_type == 'msb_bias':
            # MSB bias: top 16 bits always small
            r = random.randint(1, 1 << 240)
            values.append(r)
        elif bias_type == 'pattern':
            # Alternating pattern in bytes
            pattern = random.randint(0, 255)
            r_bytes = bytes([pattern, 255 - pattern] * 16)
            r = int.from_bytes(r_bytes, 'big') % P
            values.append(r if r > 0 else 1)
        elif bias_type == 'low_spectral':
            # Sum of few sinusoids (low spectral entropy)
            # We simulate this by choosing R values that are close in FFT domain
            # (Simplified: just values with many repeating bit patterns)
            r = sum((random.randint(0, 1) << (i * 8)) for i in range(32) if i % 4 == 0)
            values.append(r % P if r > 0 else 1)
    return values


def generate_training_data(n_samples=50000, sigs_per_sample=20):
    """Generate labeled training data: (features, label) pairs."""
    print(f"  Generating {n_samples} training samples...")
    X = []
    y = []

    bias_types = ['lsb', 'small', 'lcg', 'lfsr', 'repeated', 'msb_bias', 'pattern', 'entropy_reversal', 'low_spectral']

    for i in range(n_samples):
        if i % 2 == 0:
            # Secure (label 0)
            r_vals = generate_random_r_values(sigs_per_sample)
            label = 0
        else:
            # Weak (label 1)
            bias = random.choice(bias_types)
            if bias == 'entropy_reversal':
                # Low Permutation Entropy
                base = random.randint(1, P//2)
                step = random.randint(1, 1000000)
                r_vals = [(base + i * step) % P for i in range(sigs_per_sample)]
            else:
                r_vals = generate_biased_r_values(sigs_per_sample, bias_type=bias)
            label = 1

        feats = extract_features(r_vals)
        if feats:
            X.append(feats)
            y.append(label)

        if (i + 1) % 10000 == 0:
            print(f"    {i + 1}/{n_samples} samples generated")

    return X, y


# ============================================================
# Neural Network Model
# ============================================================

class NonceAnomalyDetector(nn.Module):
    def __init__(self, input_dim=FEATURE_DIM):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 512),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.net(x)


def train_model(epochs=30, batch_size=256, n_samples=50000):
    """Train the anomaly detector on synthetic data."""
    print("=" * 60)
    print("TRAINING NONCE ANOMALY DETECTOR")
    print("=" * 60)

    X, y = generate_training_data(n_samples=n_samples)

    # Split train/val
    split = int(0.8 * len(X))
    X_train, X_val = X[:split], X[split:]
    y_train, y_val = y[:split], y[split:]

    X_train_t = torch.FloatTensor(X_train)
    y_train_t = torch.FloatTensor(y_train).unsqueeze(1)
    X_val_t = torch.FloatTensor(X_val)
    y_val_t = torch.FloatTensor(y_val).unsqueeze(1)

    train_ds = TensorDataset(X_train_t, y_train_t)
    train_dl = DataLoader(train_ds, batch_size=batch_size, shuffle=True)

    model = NonceAnomalyDetector()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.BCELoss()

    print(f"  Training on {len(X_train)} samples, validating on {len(X_val)}")

    best_val_acc = 0
    for epoch in range(epochs):
        model.train()
        total_loss = 0
        for xb, yb in train_dl:
            pred = model(xb)
            loss = criterion(pred, yb)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        # Validation
        model.eval()
        with torch.no_grad():
            val_pred = model(X_val_t)
            val_loss = criterion(val_pred, y_val_t).item()
            val_acc = ((val_pred > 0.5).float() == y_val_t).float().mean().item()

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            torch.save(model.state_dict(), MODEL_PATH)

        if (epoch + 1) % 5 == 0:
            print(f"  Epoch {epoch+1}/{epochs} — Loss: {total_loss/len(train_dl):.4f}, "
                  f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}")

    print(f"  Training complete. Best validation accuracy: {best_val_acc:.4f}")
    print(f"  Model saved to {MODEL_PATH}")
    return model


def load_model():
    """Load a trained model from disk."""
    model = NonceAnomalyDetector()
    if os.path.exists(MODEL_PATH):
        model.load_state_dict(torch.load(MODEL_PATH, weights_only=True))
        model.eval()
        return model
    return None


# ============================================================
# Inference on Real Addresses
# ============================================================

def scan_addresses_with_nn(max_addresses=100):
    """
    Apply the trained neural network to real signature sets.
    Flag addresses with high P(vulnerable) for deeper analysis.
    """
    print("=" * 60)
    print("NEURAL NETWORK NONCE ANOMALY SCAN")
    print("=" * 60)

    # Load or train model
    model = load_model()
    if model is None:
        print("  No trained model found — training now...")
        model = train_model(epochs=30, n_samples=50000)
        model = load_model()

    # Get addresses with sufficient signatures
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT address, COUNT(*) as sig_count
        FROM signatures
        GROUP BY address
        HAVING COUNT(*) >= 4
        ORDER BY sig_count DESC
        LIMIT ?
    """, (max_addresses,))
    addresses = c.fetchall()

    if not addresses:
        print("  No addresses with sufficient signatures (need ≥4)")
        conn.close()
        return []

    print(f"  Scanning {len(addresses)} addresses with neural network...")

    flagged = []
    for addr, sig_count in addresses:
        c.execute("SELECT r_int FROM signatures WHERE address = ?", (addr,))
        rows = c.fetchall()
        r_values = [int(r[0]) for r in rows if r[0]]

        if len(r_values) < 4:
            continue

        feats = extract_features(r_values)
        if feats is None:
            continue

        with torch.no_grad():
            x = torch.FloatTensor([feats])
            prob = model(x).item()

        if prob > 0.5:
            risk = "HIGH" if prob > 0.8 else "MEDIUM"
            print(f"  ⚠ {addr[:35]}... P(vuln)={prob:.4f} [{risk}] ({sig_count} sigs)")
            
            # Breakdown of Reverse Entropy Metrics
            rev_entropy_feats = get_reverse_entropy_features(r_values)
            pe3 = rev_entropy_feats[0]
            samp_en = rev_entropy_feats[3]
            spec_en = rev_entropy_feats[13]
            lz_lsb = rev_entropy_feats[18]
            
            print(f"    - Reverse Entropy Stats: PE={pe3:.3f}, SampEn={samp_en:.3f}, SpecEn={spec_en:.3f}, LZ={lz_lsb:.3f}")
            if pe3 < 0.6: print(f"      [!] Low Permutation Entropy - suggests LCG/LFSR pattern")
            if spec_en < 0.5: print(f"      [!] Low Spectral Entropy - suggests periodic/patterned nonces")
            if lz_lsb < 0.4: print(f"      [!] Low Lempel-Ziv Complexity - suggests simple repeatable pattern")
            
            flagged.append({
                'address': addr,
                'probability': prob,
                'risk': risk,
                'sig_count': sig_count,
                'entropy_metrics': {
                    'pe': pe3, 'samp_en': samp_en, 'spec_en': spec_en, 'lz': lz_lsb
                }
            })
            add_finding(addr, 'Neural Net Anomaly',
                        details=f'P(vulnerable)={prob:.4f}, PE={pe3:.2f}, SpecEn={spec_en:.2f}',
                        severity='High' if prob > 0.8 else 'Medium')
        else:
            print(f"  ✓ {addr[:35]}... P(vuln)={prob:.4f} [OK] ({sig_count} sigs)")

    conn.close()

    # Summary
    print(f"\n  Results: {len(flagged)}/{len(addresses)} addresses flagged")
    if flagged:
        print(f"  Flagged addresses (sorted by risk):")
        for f in sorted(flagged, key=lambda x: x['probability'], reverse=True):
            print(f"    {f['address'][:40]}... P={f['probability']:.4f}")

    return flagged


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'train':
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 50000
        train_model(n_samples=n)
    else:
        scan_addresses_with_nn()
