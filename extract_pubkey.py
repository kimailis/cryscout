import json
import hashlib
import base58
from ecdsa import VerifyingKey, SECP256k1, SigningKey
from ecdsa.util import sigdecode_der

def pubkey_to_address(pubkey_bytes):
    sha256 = hashlib.sha256(pubkey_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    vh = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(vh).digest()).digest()[:4]
    return base58.b58encode(vh + checksum).decode()

def extract_pubkey(filename, target_address):
    with open(filename, "r") as f:
        sigs = json.load(f)
    
    print(f"Attempting to extract public key from {len(sigs)} signatures for {target_address}...")
    
    for i, sig_data in enumerate(sigs):
        r, s, z = sig_data['r'], sig_data['s'], sig_data['z']
        
        # Recover candidate public keys from (r, s, z)
        # r is x-coordinate of R. y^2 = x^3 + 7 mod P
        # There are two possible y values for each x.
        P_curve = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        x = r
        y_sq = (pow(x, 3, P_curve) + 7) % P_curve
        # Tonelli-Shanks for y = sqrt(y_sq) mod P_curve
        # For SECP256K1, P_curve % 4 == 3, so y = y_sq^((P+1)/4)
        y = pow(y_sq, (P_curve + 1) // 4, P_curve)
        
        if pow(y, 2, P_curve) != y_sq:
            continue
            
        candidates = []
        for y_val in [y, P_curve - y]:
            # R = (x, y)
            # s = (z + r*d) / k => k*s = z + r*d => k = (z + r*d)/s
            # k*G = (z/s)*G + (r/s)*Q
            # R = (z/s)*G + (r/s)*Q
            # (r/s)*Q = R - (z/s)*G
            # Q = (s/r)*(R - (z/s)*G)
            
            # Use ecdsa's VerifyingKey.from_public_point
            from ecdsa.ellipticcurve import Point
            R = Point(SECP256k1.curve, x, y_val)
            
            G = SECP256k1.generator
            n = SECP256k1.order
            
            s_inv = pow(s, -1, n)
            r_inv = pow(r, -1, n)
            
            # Q = r_inv * (s*R - z*G)
            Q = r_inv * (s * R + (n - z) * G)
            
            # Check compressed and uncompressed
            vk = VerifyingKey.from_public_point(Q, curve=SECP256k1)
            
            pub_uncompressed = vk.to_string('uncompressed')
            pub_compressed = vk.to_string('compressed')
            
            if pubkey_to_address(pub_uncompressed) == target_address:
                print(f"Found PUBLIC KEY (Uncompressed): {pub_uncompressed.hex()}")
                return pub_uncompressed
            if pubkey_to_address(pub_compressed) == target_address:
                print(f"Found PUBLIC KEY (Compressed): {pub_compressed.hex()}")
                return pub_compressed

    print("Could not find public key.")
    return None

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python3 extract_pubkey.py <sigs.json> <address>")
    else:
        extract_pubkey(sys.argv[1], sys.argv[2])
