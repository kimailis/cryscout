from ecdsa import SECP256k1
from db_manager import add_finding, get_connection

def recover_from_collision(r, s1, s2, z1, z2):
    n = SECP256k1.order
    def inv(a, n):
        return pow(a, n - 2, n)

    # k = (z1 - z2) / (s1 - s2) mod n
    k = ((z1 - z2) * inv(s1 - s2, n)) % n
    # priv = (s1 * k - z1) / r mod n
    priv = ((s1 * k - z1) * inv(r, n)) % n
    return priv, k

# Data from tx_preimage_reconstructor.py
# Input 0: R0, S0, Z0
# Input 1: R1, S1, Z1
# Wait, the R values in the output were DIFFERENT. 
# R0: 0xd46fe308d8b7a1a6f0b76d42c1a49ebe183763c9c26dca129401d0f252b085
# R1: 0x637c4d66225c0e96f7b7ed08dae69117d2b4347c541fb5ef4169447a37aa4c05
# If R values are different, it's NOT a simple R-collision. 

# Let's check the output again. 
# Ah, the previous `recover_key.py` run (in the prompt history) said:
# "!!! COLLISION FOUND IN THIS TX !!!"
# "R: 0xd46fe308d8b7a1..."
# Maybe I misread the tx_preimage_reconstructor output or there are MORE than 2 inputs.

if __name__ == "__main__":
    import requests
    TXID = "c097a280bfed180a99d579053473408b8f0caa1c886bbc819fda65b08d590728"
    resp = requests.get(f"https://mempool.space/api/tx/{TXID}")
    tx = resp.json()
    print(f"TX {TXID} has {len(tx['vin'])} inputs.")
    for i, vin in enumerate(tx['vin']):
         addr = vin['prevout']['scriptpubkey_address']
         print(f"Input {i}: {addr}")
