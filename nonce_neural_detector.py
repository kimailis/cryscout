#!/usr/bin/env python3
"""
Phase 3.1 — Neural Network Nonce Anomaly Detector & Spectral Bias

Uses a PyTorch binary classifier trained on synthetic data to detect
hidden patterns in ECDSA nonce (R-value) distributions that statistical
tests might miss. Also implements an LSTM model for Spectral Bias detection.

Architecture:
  - Feed-Forward Model: Binary Classifier → P(vulnerable)
  - Spectral Bias LSTM: Sequence Prediction → Next bits of PRNG sequence
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
LSTM_MODEL_PATH = 'spectral_bias_lstm.pt'


# ============================================================
# Feature Extraction (Feed-Forward)
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
        signal = [float(r.bit_length()) for r in r_values[:256]]
        pad_len = 1
        while pad_len < len(signal):
            pad_len *= 2
        signal.extend([0.0] * (pad_len - len(signal)))
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
# Sequence Extraction (LSTM)
# ============================================================

def extract_sequence(r_values, max_len=20):
    """Extract a bit sequence for the LSTM model. Focuses on the lowest 64 bits to find PRNG connections."""
    seq = []
    for r in r_values[:max_len]:
        bits = [(r >> i) & 1 for i in range(64)]
        seq.append(bits)
    # Pad if necessary
    while len(seq) < max_len:
        seq.append([0]*64)
    return seq


# ============================================================
# Synthetic Data Generation & Mutation Engine
# ============================================================

def generate_random_r_values(count):
    return [random.randint(1, P - 1) for _ in range(count)]

def generate_biased_r_values(count, bias_type='lsb'):
    values = []
    if bias_type == 'lcg':
        a = random.randint(1, P - 1)
        b = random.randint(1, P - 1)
        k = random.randint(1, P - 1)
        for _ in range(count):
            values.append(k % P)
            k = (a * k + b) % P
        return values
    
    if bias_type == 'lfsr':
        state = random.randint(1, (1 << 256) - 1)
        for _ in range(count):
            values.append(state % P)
            fb = (state ^ (state >> 2) ^ (state >> 3) ^ (state >> 5)) & 1
            state = (state >> 1) | (fb << 255)
        return values

    for _ in range(count):
        if bias_type == 'lsb':
            r = random.randint(1, P - 1)
            r = (r & ~0xFF) | 0x42
            values.append(r)
        elif bias_type == 'small':
            r = random.randint(1, 1 << 128)
            values.append(r)
        elif bias_type == 'repeated':
            base_r = random.randint(1, P - 1)
            if random.random() < 0.3:
                values.append(base_r)
            else:
                values.append(random.randint(1, P - 1))
        elif bias_type == 'msb_bias':
            r = random.randint(1, 1 << 240)
            values.append(r)
        elif bias_type == 'pattern':
            pattern = random.randint(0, 255)
            r_bytes = bytes([pattern, 255 - pattern] * 16)
            r = int.from_bytes(r_bytes, 'big') % P
            values.append(r if r > 0 else 1)
        elif bias_type == 'low_spectral':
            r = sum((random.randint(0, 1) << (i * 8)) for i in range(32) if i % 4 == 0)
            values.append(r % P if r > 0 else 1)
    return values

def generate_mutated_r_values(count):
    """Generates heavily mutated, composite biased sequences to force continuous AI adaptation."""
    values = []
    # Mix 1 to 3 random bias types together
    mutations = random.sample(['lsb', 'small', 'msb_bias', 'low_spectral', 'bit_flip', 'periodic_bias', 'block_mask'], k=random.randint(1, 3))
    
    # Start with a base generator (either random, LCG, or LFSR)
    base_gen = random.choice(['random', 'lcg', 'lfsr'])
    if base_gen == 'random':
        base_seq = generate_random_r_values(count)
    else:
        base_seq = generate_biased_r_values(count, bias_type=base_gen)
        
    for i in range(count):
        r = base_seq[i]
        # Apply selected genetic mutations to the sequence
        for m in mutations:
            if m == 'lsb':
                mask = (1 << random.randint(1, 12)) - 1
                val = random.randint(0, mask)
                r = (r & ~mask) | val
            elif m == 'small':
                r = r % (1 << random.randint(64, 224))
            elif m == 'msb_bias':
                r = r | (1 << random.randint(200, 255))
            elif m == 'low_spectral':
                if i % 2 == 0: r = r ^ (1 << (i % 256))
            elif m == 'bit_flip':
                if random.random() < 0.1:
                    r = r ^ (1 << random.randint(0, 255))
            elif m == 'periodic_bias':
                # Bias that changes periodically
                if (i // 5) % 2 == 0:
                    r = (r & ~0xFFF) | 0xABC
            elif m == 'block_mask':
                # Mask out a specific 32-bit block
                block_start = random.randint(0, 7) * 32
                r = r & ~(0xFFFFFFFF << block_start)
        values.append(r if r > 0 else 1)
    return values

def generate_training_data(n_samples=50000, sigs_per_sample=20):
    print(f"  Generating {n_samples} training samples for FFNN (with Mutations)...")
    X, y = [], []
    bias_types = ['lsb', 'small', 'lcg', 'lfsr', 'repeated', 'msb_bias', 'pattern', 'entropy_reversal', 'low_spectral', 'mutated']

    for i in range(n_samples):
        if i % 2 == 0:
            r_vals = generate_random_r_values(sigs_per_sample)
            label = 0
        else:
            bias = random.choice(bias_types)
            if bias == 'entropy_reversal':
                base = random.randint(1, P//2)
                step = random.randint(1, 1000000)
                r_vals = [(base + i * step) % P for i in range(sigs_per_sample)]
            elif bias == 'mutated':
                r_vals = generate_mutated_r_values(sigs_per_sample)
            else:
                r_vals = generate_biased_r_values(sigs_per_sample, bias_type=bias)
            label = 1

        feats = extract_features(r_vals)
        if feats:
            X.append(feats)
            y.append(label)

    return X, y


def generate_lstm_training_data(n_samples=10000, seq_len=10):
    print(f"  Generating {n_samples} training samples for LSTM (with Mutations)...")
    X, y = [], []
    # We train the LSTM to predict the next 64 bits of a sequence given previous bits
    for i in range(n_samples):
        if i % 2 == 0:
            r_vals = generate_random_r_values(seq_len + 1)
        else:
            if random.random() < 0.3:
                r_vals = generate_mutated_r_values(seq_len + 1)
            else:
                # Generate LCG or LFSR sequences which have strong spectral bias / predictability
                r_vals = generate_biased_r_values(seq_len + 1, bias_type=random.choice(['lcg', 'lfsr']))
        
        seq = extract_sequence(r_vals, max_len=seq_len + 1)
        X.append(seq[:-1]) # Input sequence
        y.append(seq[-1])  # Target next step
    return X, y


# ============================================================
# Neural Network Models & Storage
# ============================================================

_ff_model_cache = None
_lstm_model_cache = None
_last_load_time = 0

def save_model_atomic(model, path):
    """Saves a model to a temporary file and then replaces the target path atomically."""
    import tempfile
    temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)) or ".")
    try:
        torch.save(model.state_dict(), temp_path)
        os.close(temp_fd)
        os.replace(temp_path, path)
    except Exception as e:
        if os.path.exists(temp_path):
            try: os.close(temp_fd) 
            except: pass
            os.remove(temp_path)
        raise e

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

class SpectralBiasLSTM(nn.Module):
    def __init__(self, input_size=64, hidden_size=128, num_layers=2):
        super().__init__()
        self.hidden_size = hidden_size
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True, dropout=0.2)
        self.fc = nn.Linear(hidden_size, input_size)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        out, _ = self.lstm(x)
        # We only care about the prediction after the last step
        last_out = out[:, -1, :]
        return self.sigmoid(self.fc(last_out))


def train_model(epochs=30, batch_size=256, n_samples=50000, model=None):
    print("=" * 60)
    print(f"EVOLVING FFNN NONCE ANOMALY DETECTOR ({n_samples} samples)")
    print("=" * 60)

    X, y = generate_training_data(n_samples=n_samples)

    split = int(0.8 * len(X))
    X_train, X_val = X[:split], X[split:]
    y_train, y_val = y[:split], y[split:]

    X_train_t = torch.FloatTensor(X_train)
    y_train_t = torch.FloatTensor(y_train).unsqueeze(1)
    X_val_t = torch.FloatTensor(X_val)
    y_val_t = torch.FloatTensor(y_val).unsqueeze(1)

    train_ds = TensorDataset(X_train_t, y_train_t)
    train_dl = DataLoader(train_ds, batch_size=batch_size, shuffle=True)

    if model is None:
        model = NonceAnomalyDetector()
        if os.path.exists(MODEL_PATH):
            try:
                model.load_state_dict(torch.load(MODEL_PATH, weights_only=True))
            except:
                pass # Start fresh if corrupt
                
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.BCELoss()

    best_val_acc = 0
    for epoch in range(epochs):
        model.train()
        for xb, yb in train_dl:
            pred = model(xb)
            loss = criterion(pred, yb)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            val_pred = model(X_val_t)
            val_acc = ((val_pred > 0.5).float() == y_val_t).float().mean().item()

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            save_model_atomic(model, MODEL_PATH)

    print(f"  FFNN Training complete. Best validation accuracy: {best_val_acc:.4f}")
    return model


def train_lstm_model(epochs=20, batch_size=128, n_samples=10000, model=None):
    print("=" * 60)
    print(f"EVOLVING LSTM SPECTRAL BIAS DETECTOR ({n_samples} samples)")
    print("=" * 60)

    X, y = generate_lstm_training_data(n_samples=n_samples)
    split = int(0.8 * len(X))
    
    X_train_t = torch.FloatTensor(X[:split])
    y_train_t = torch.FloatTensor(y[:split])
    X_val_t = torch.FloatTensor(X[split:])
    y_val_t = torch.FloatTensor(y[split:])

    train_ds = TensorDataset(X_train_t, y_train_t)
    train_dl = DataLoader(train_ds, batch_size=batch_size, shuffle=True)

    if model is None:
        model = SpectralBiasLSTM()
        if os.path.exists(LSTM_MODEL_PATH):
            try:
                model.load_state_dict(torch.load(LSTM_MODEL_PATH, weights_only=True))
            except:
                pass

    optimizer = optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.BCELoss()

    best_val_loss = float('inf')
    for epoch in range(epochs):
        model.train()
        for xb, yb in train_dl:
            pred = model(xb)
            loss = criterion(pred, yb)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            val_pred = model(X_val_t)
            val_loss = criterion(val_pred, y_val_t).item()
            
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            save_model_atomic(model, LSTM_MODEL_PATH)
            
    print(f"  LSTM Training complete. Best validation loss: {best_val_loss:.4f}")
    return model


def load_models(force_reload=False):
    global _ff_model_cache, _lstm_model_cache, _last_load_time
    
    ff_exists = os.path.exists(MODEL_PATH)
    lstm_exists = os.path.exists(LSTM_MODEL_PATH)
    
    if not force_reload and _ff_model_cache and _lstm_model_cache:
        mtime_ff = os.path.getmtime(MODEL_PATH) if ff_exists else 0
        mtime_lstm = os.path.getmtime(LSTM_MODEL_PATH) if lstm_exists else 0
        if mtime_ff <= _last_load_time and mtime_lstm <= _last_load_time:
            return _ff_model_cache, _lstm_model_cache

    _ff_model_cache = NonceAnomalyDetector()
    if ff_exists:
        try:
            _ff_model_cache.load_state_dict(torch.load(MODEL_PATH, weights_only=True))
            _ff_model_cache.eval()
        except Exception as e:
            print(f" [!] Error loading FFNN model: {e}")
            _ff_model_cache = train_model()
    else:
        _ff_model_cache = train_model()
        
    _lstm_model_cache = SpectralBiasLSTM()
    if lstm_exists:
        try:
            _lstm_model_cache.load_state_dict(torch.load(LSTM_MODEL_PATH, weights_only=True))
            _lstm_model_cache.eval()
        except Exception as e:
            print(f" [!] Error loading LSTM model: {e}")
            _lstm_model_cache = train_lstm_model()
    else:
        _lstm_model_cache = train_lstm_model()
        
    _last_load_time = time.time()
    return _ff_model_cache, _lstm_model_cache


# ============================================================
# Inference on Real Addresses
# ============================================================

def scan_addresses_with_nn(addresses=None):
    if addresses is None:
        conn = get_connection()
        c = conn.cursor()
        c.execute("""
            SELECT address, COUNT(*) as sig_count
            FROM signatures
            GROUP BY address
            HAVING COUNT(*) >= 4
            ORDER BY sig_count DESC
            LIMIT 20
        """)
        addresses = [a[0] for a in c.fetchall()]
        conn.close()

    if not addresses:
        return []

    print(f"  Scanning {len(addresses)} addresses with Neural Networks (FFNN & LSTM Spectral Bias)...")
    ff_model, lstm_model = load_models()

    conn = get_connection()
    c = conn.cursor()
    flagged = []
    
    for addr in addresses:
        c.execute("SELECT r_int FROM signatures WHERE address = ? ORDER BY id ASC", (addr,))
        r_values = [int(r[0]) for r in c.fetchall() if r[0]]

        if len(r_values) < 4:
            continue

        # 1. FFNN Feature extraction
        feats = extract_features(r_values)
        prob_ff = 0
        if feats:
            with torch.no_grad():
                prob_ff = ff_model(torch.FloatTensor([feats])).item()

        # 2. LSTM Spectral Bias extraction
        prob_spectral = 0
        if len(r_values) >= 5:
            seq = extract_sequence(r_values, max_len=len(r_values))
            input_seq = torch.FloatTensor([seq[:-1]])
            target_out = torch.FloatTensor(seq[-1])
            with torch.no_grad():
                pred = lstm_model(input_seq).squeeze(0)
                # Calculate mean squared error between prediction and actual next bits
                # Lower MSE = highly predictable = Spectral Bias
                mse = ((pred - target_out) ** 2).mean().item()
                # Convert MSE to a probability score (arbitrary threshold scaling for demonstration)
                # Random guessing MSE is ~0.25. If MSE < 0.15, it's highly predictable.
                prob_spectral = max(0, min(1, (0.25 - mse) * 10))

        prob_max = max(prob_ff, prob_spectral)
        if prob_max > 0.5:
            risk = "HIGH" if prob_max > 0.8 else "MEDIUM"
            print(f"  ⚠ {addr[:35]}... P(vuln)={prob_max:.4f} (FFNN: {prob_ff:.2f}, LSTM: {prob_spectral:.2f}) [{risk}]")
            
            flagged.append({
                'address': addr,
                'probability': prob_max,
                'risk': risk,
            })
            
            if prob_spectral > 0.5:
                add_finding(addr, 'Spectral Bias Anomaly (LSTM)',
                            details=f'LSTM Predictability P={prob_spectral:.4f}',
                            severity='High' if prob_spectral > 0.8 else 'Medium')
            elif prob_ff > 0.5:
                add_finding(addr, 'Neural Net Anomaly',
                            details=f'FFNN P(vulnerable)={prob_ff:.4f}',
                            severity='High' if prob_ff > 0.8 else 'Medium')

    conn.close()
    return flagged


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'train':
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 50000
        train_model(n_samples=n)
        train_lstm_model(n_samples=n//5)
    else:
        scan_addresses_with_nn()
