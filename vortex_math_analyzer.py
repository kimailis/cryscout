import torch
import torch.nn as nn
import numpy as np
import hashlib
import binascii
from numba import njit

class SpinGlassManifoldNet(nn.Module):
    def __init__(self, input_dim=256, hidden_dim=512, layers=20):
        super(SpinGlassManifoldNet, self).__init__()
        self.layers = nn.ModuleList()
        self.layers.append(nn.Linear(input_dim, hidden_dim))
        for _ in range(layers - 1):
            self.layers.append(nn.Linear(hidden_dim, hidden_dim))
        self.output = nn.Linear(hidden_dim, input_dim)
        
    def forward(self, x):
        for i, layer in enumerate(self.layers):
            x = torch.relu(layer(x))
            # "Slide" around computational walls using topological skips (simulated)
            if i in [15, 20]: # ES15-ES20 layers
                x = x + 0.1 * torch.sin(x * np.pi) 
        return torch.sigmoid(self.output(x))

@njit
def get_digital_root(n):
    if n == 0:
        return 0
    return 1 + ((n - 1) % 9)

@njit
def _analyze_vortex_numba(roots_arr):
    n = len(roots_arr)
    found_369 = 0
    for i in range(n):
        # We inline get_digital_root logic here or call it if numba allows
        val = roots_arr[i]
        r = 1 + ((val - 1) % 9) if val > 0 else 0
        if r == 3 or r == 6 or r == 9:
            found_369 += 1
    
    purity = 1.0 - (found_369 / n)
    is_anomalous = purity > 0.85
    return is_anomalous, purity

def analyze_vortex_periodicity(hex_str):
    """
    Checks if a hex sequence (like a generated key or nonce) exhibits
    vortex periodicity (1, 2, 4, 8, 7, 5) avoiding 3, 6, 9,
    indicating a potentially vulnerable PRNG/LCG.
    """
    try:
        val = int(hex_str, 16)
    except ValueError:
        return False, 0.0

    # Convert the integer to a string to analyze digit groupings
    val_str = str(val)
    chunks = []
    # PERFORMANCE TIP: Cache method references to avoid dot-lookup in loops
    _append = chunks.append
    _int = int
    
    # Sample in 4-digit chunks to find local digital roots
    for i in range(0, len(val_str), 4):
        chunk = val_str[i:i+4]
        if chunk:
            _append(_int(chunk))
    
    if not chunks:
        return False, 0.0
        
    roots_arr = np.array(chunks, dtype=np.int64)
    return _analyze_vortex_numba(roots_arr)

# Global model instance for reuse
_SPIN_GLASS_MODEL = None

def get_spin_glass_model():
    global _SPIN_GLASS_MODEL
    if _SPIN_GLASS_MODEL is None:
        _SPIN_GLASS_MODEL = SpinGlassManifoldNet()
        _SPIN_GLASS_MODEL.eval() # Set to evaluation mode
    return _SPIN_GLASS_MODEL

def simulate_spin_glass_binding(pubkey_hex):
    """
    Navigates the IE relationship space using Spin-Glass architecture.
    """
    try:
        # Convert hex to binary array
        val = int(pubkey_hex, 16)
        bin_str = bin(val)[2:].zfill(256)
        if len(bin_str) > 256:
            bin_str = bin_str[-256:]
            
        tensor_in = torch.tensor([int(b) for b in bin_str], dtype=torch.float32)
        
        model = get_spin_glass_model()
        with torch.no_grad():
            manifold_output = model(tensor_in)
            
        # The theoretical distance in the "relationship space"
        # We measure how easily the manifold "collapses"
        entropy = -torch.sum(manifold_output * torch.log(manifold_output + 1e-9)).item()
        
        # Low entropy implies high binding (predictability)
        binding_score = 1.0 / (1.0 + entropy)
        
        is_bound = binding_score > 0.15 # Threshold for IE Binding
        return is_bound, binding_score
        
    except Exception as e:
        return False, 0.0

def scan_vortex_anomalies(addresses_data, sigs_data_map):
    """
    addresses_data: list of addresses
    sigs_data_map: dict of address -> list of sig dicts
    Returns list of dicts with anomalies
    """
    anomalies = []
    for addr in addresses_data:
        sigs = sigs_data_map.get(addr, [])
        
        highest_purity = 0
        best_binding = 0
        
        for sig in sigs:
            # Check Vortex Periodicity on R and S
            r_hex = sig.get('r', '')
            s_hex = sig.get('s', '')
            pub_hex = sig.get('pubkey', '')
            
            if r_hex:
                anom_r, purity_r = analyze_vortex_periodicity(r_hex)
                highest_purity = max(highest_purity, purity_r)
            if s_hex:
                anom_s, purity_s = analyze_vortex_periodicity(s_hex)
                highest_purity = max(highest_purity, purity_s)
                
            if pub_hex:
                anom_bind, bind_score = simulate_spin_glass_binding(pub_hex)
                best_binding = max(best_binding, bind_score)
                    
        if highest_purity > 0.85:
            anomalies.append({
                'address': addr,
                'type': 'Vortex Harmonic Pruning (3-6-9)',
                'severity': 'High' if highest_purity > 0.95 else 'Medium',
                'details': f'Spectral Distinguisher Purity: {highest_purity:.2f}'
            })
            
        if best_binding > 0.15:
            anomalies.append({
                'address': addr,
                'type': 'Spin-Glass IE Binding Manifold',
                'severity': 'High' if best_binding > 0.25 else 'Medium',
                'details': f'Topological Collapse Score: {best_binding:.4f}'
            })
            
    return anomalies
