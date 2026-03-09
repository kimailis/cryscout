import requests
import hashlib
import time
import struct
import sys

def get_real_z_segwit(tx_data, vin_index):
    import struct
    def double_sha256(data): return hashlib.sha256(hashlib.sha256(data).digest()).digest()
    def get_varint_bytes(n):
        if n < 0xfd: return struct.pack('<B', n)
        elif n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
        elif n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
        else: return b'\xff' + struct.pack('<Q', n)
    
    version = struct.pack('<I', tx_data['version'])
    prevouts_raw = bytearray()
    for vin in tx_data['vin']:
        prevouts_raw.extend(bytes.fromhex(vin['txid'])[::-1])
        prevouts_raw.extend(struct.pack('<I', vin['vout']))
    hash_prevouts = double_sha256(prevouts_raw)
    sequence_raw = bytearray()
    for vin in tx_data['vin']:
        sequence_raw.extend(struct.pack('<I', vin['sequence']))
    hash_sequence = double_sha256(sequence_raw)
    target_vin = tx_data['vin'][vin_index]
    outpoint = bytes.fromhex(target_vin['txid'])[::-1] + struct.pack('<I', target_vin['vout'])
    spk = target_vin['prevout']['scriptpubkey']
    pkh = spk[4:] 
    script_code = bytes.fromhex("1976a914" + pkh + "88ac")
    value = struct.pack('<Q', target_vin['prevout']['value'])
    sequence = struct.pack('<I', target_vin['sequence'])
    outputs_raw = bytearray()
    for vout in tx_data['vout']:
        outputs_raw.extend(struct.pack('<Q', vout['value']))
        spk_bytes = bytes.fromhex(vout['scriptpubkey'])
        outputs_raw.extend(get_varint_bytes(len(spk_bytes)))
        outputs_raw.extend(spk_bytes)
    hash_outputs = double_sha256(outputs_raw)
    locktime = struct.pack('<I', tx_data['locktime'])
    sighash_type = struct.pack('<I', 1)
    preimage = version + hash_prevouts + hash_sequence + outpoint + script_code + value + sequence + hash_outputs + locktime + sighash_type
    return int(double_sha256(preimage).hex(), 16)

def get_real_z(tx_data, vin_index):
    # Determine type and call appropriate reconstruction
    vin = tx_data['vin'][vin_index]
    spk_type = vin['prevout']['scriptpubkey_type']
    if spk_type == 'v0_p2wpkh':
        return get_real_z_segwit(tx_data, vin_index)
    else:
        # Placeholder for legacy Z reconstruction (re-use from tx_preimage_reconstructor if needed)
        # For R reuse check, we only need Z if reuse is found.
        return 0 

def check_r_reuse(address):
    print(f"Checking {address} for R reuse (paging)...")
    last_txid = None
    seen_r = {}
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    for page in range(20):
        url = f"https://mempool.space/api/address/{address}/txs/chain"
        if last_txid: url += f"/{last_txid}"
        resp = requests.get(url)
        if resp.status_code != 200: break
        txs = resp.json()
        if not txs: break
        
        for tx in txs:
            txid = tx['txid']
            last_txid = txid
            for i, vin in enumerate(tx.get('vin', [])):
                if vin.get('prevout', {}).get('scriptpubkey_address') == address:
                    scriptsig = vin.get('scriptsig', '')
                    witness = vin.get('witness', [])
                    sigs = []
                    if scriptsig: sigs.append(scriptsig)
                    if witness: sigs.extend(witness)
                    
                    for sig_hex in sigs:
                        try:
                            sig_bytes = bytes.fromhex(sig_hex)
                            idx = sig_bytes.find(b'\x30')
                            if idx == -1: continue
                            r_tag_idx = idx + 2
                            r_len = sig_bytes[r_tag_idx+1]
                            r_val = sig_bytes[r_tag_idx+2 : r_tag_idx+2+r_len]
                            r_int = int.from_bytes(r_val, 'big')
                            
                            s_tag_idx = r_tag_idx + 2 + r_len
                            s_len = sig_bytes[s_tag_idx+1]
                            s_int = int.from_bytes(sig_bytes[s_tag_idx+2 : s_tag_idx+2+s_len], 'big')
                            
                            if r_int in seen_r:
                                old = seen_r[r_int]
                                if old['txid'] == txid: continue
                                print(f"!!! R REUSE DETECTED !!!")
                                # ... key recovery logic ...
                                return True
                            else:
                                seen_r[r_int] = {'txid': txid, 's': s_int}
                        except: pass
        time.sleep(0.5)
    print("No reuse found.")
    return False

import sys

if __name__ == "__main__":
    if len(sys.argv) > 1:
        check_r_reuse(sys.argv[1])
    else:
        check_r_reuse('bc1ql5hlr8ugqlav2ct3p0c5zwvjyarf0afgh6f5v6')
