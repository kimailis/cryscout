import requests
import hashlib
import struct
import re
import time
import aiohttp
import asyncio

# SECP256K1 Curve Order
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def get_varint_bytes(n):
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)

def get_real_z_legacy(tx_data, vin_index):
    """
    Reconstructs the Sighash Preimage for a Legacy (P2PKH) input.
    """
    builder = bytearray()
    builder.extend(struct.pack('<I', tx_data['version']))

    # Inputs
    builder.extend(get_varint_bytes(len(tx_data['vin'])))
    for i, vin in enumerate(tx_data['vin']):
        builder.extend(bytes.fromhex(vin['txid'])[::-1])
        builder.extend(struct.pack('<I', vin['vout']))
        if i == vin_index:
            script_bytes = bytes.fromhex(vin['prevout']['scriptpubkey'])
            builder.extend(get_varint_bytes(len(script_bytes)))
            builder.extend(script_bytes)
        else:
            builder.extend(b'\x00')
        builder.extend(struct.pack('<I', vin['sequence']))

    # Outputs
    builder.extend(get_varint_bytes(len(tx_data['vout'])))
    for vout in tx_data['vout']:
        builder.extend(struct.pack('<Q', vout['value']))
        script_bytes = bytes.fromhex(vout['scriptpubkey'])
        builder.extend(get_varint_bytes(len(script_bytes)))
        builder.extend(script_bytes)

    builder.extend(struct.pack('<I', tx_data['locktime']))
    builder.extend(struct.pack('<I', 1)) # SIGHASH_ALL
    
    return int(double_sha256(builder).hex(), 16)

def get_real_z_segwit(tx_data, vin_index):
    """
    Reconstructs the Sighash Preimage for a SegWit v0 (P2WPKH) input (BIP143).
    """
    # 1. Version
    version = struct.pack('<I', tx_data['version'])
    
    # 2. HashPrevouts
    prevouts_raw = bytearray()
    for vin in tx_data['vin']:
        prevouts_raw.extend(bytes.fromhex(vin['txid'])[::-1])
        prevouts_raw.extend(struct.pack('<I', vin['vout']))
    hash_prevouts = double_sha256(prevouts_raw)
    
    # 3. HashSequence
    sequence_raw = bytearray()
    for vin in tx_data['vin']:
        sequence_raw.extend(struct.pack('<I', vin['sequence']))
    hash_sequence = double_sha256(sequence_raw)
    
    # 4. Outpoint
    target_vin = tx_data['vin'][vin_index]
    outpoint = bytes.fromhex(target_vin['txid'])[::-1] + struct.pack('<I', target_vin['vout'])
    
    # 5. ScriptCode (for P2WPKH it's 1976a914{20-byte-pubkey-hash}88ac)
    # We get the pubkey hash from the scriptPubKey (0014{20-byte-hash})
    spk = target_vin['prevout']['scriptpubkey']
    pkh = spk[4:] # Skip 0014
    script_code = bytes.fromhex("1976a914" + pkh + "88ac")
    
    # 6. Value
    value = struct.pack('<Q', target_vin['prevout']['value'])
    
    # 7. Sequence
    sequence = struct.pack('<I', target_vin['sequence'])
    
    # 8. HashOutputs
    outputs_raw = bytearray()
    for vout in tx_data['vout']:
        outputs_raw.extend(struct.pack('<Q', vout['value']))
        spk_bytes = bytes.fromhex(vout['scriptpubkey'])
        outputs_raw.extend(get_varint_bytes(len(spk_bytes)))
        outputs_raw.extend(spk_bytes)
    hash_outputs = double_sha256(outputs_raw)
    
    # 9. Locktime
    locktime = struct.pack('<I', tx_data['locktime'])
    
    # 10. SighashType
    sighash_type = struct.pack('<I', 1) # SIGHASH_ALL
    
    preimage = version + hash_prevouts + hash_sequence + outpoint + script_code + value + sequence + hash_outputs + locktime + sighash_type
    return int(double_sha256(preimage).hex(), 16)

def get_real_z(tx_data, vin_index):
    try:
        vin = tx_data['vin'][vin_index]
        spk_type = vin['prevout']['scriptpubkey_type']
        
        if spk_type == 'p2pkh':
            return get_real_z_legacy(tx_data, vin_index)
        elif spk_type == 'v0_p2wpkh':
            return get_real_z_segwit(tx_data, vin_index)
        else:
            return None
    except:
        return None

async def async_get_real_z(session, txid, vin_index):
    try:
        url = f"https://mempool.space/api/tx/{txid}"
        async with session.get(url, timeout=10) as resp:
            if resp.status != 200: return None
            tx_data = await resp.json()
            return get_real_z(tx_data, vin_index)
    except:
        return None

def parse_der(sig_hex):
    try:
        start = sig_hex.find('30')
        if start == -1: return None, None
        data = bytes.fromhex(sig_hex[start:])
        if data[0] != 0x30: return None, None
        r_len = data[3]
        r_val = int.from_bytes(data[4:4+r_len], 'big')
        s_tag_idx = 4 + r_len
        if data[s_tag_idx] != 0x02: return None, None
        s_len = data[s_tag_idx+1]
        s_val = int.from_bytes(data[s_tag_idx+2:s_tag_idx+2+s_len], 'big')
        return r_val, s_val
    except:
        return None, None

async def async_extract_sigs_from_txids(address, txids, max_sigs=256):
    full_data = []
    async with aiohttp.ClientSession() as session:
        # Fetch TX data in parallel
        tasks = []
        for txid in txids[:max_sigs]:
            tasks.append(session.get(f"https://mempool.space/api/tx/{txid}", timeout=10))
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, resp in enumerate(responses):
            if isinstance(resp, Exception) or resp.status != 200: continue
            tx = await resp.json()
            txid = txids[i]
            
            for vin_idx, vin in enumerate(tx.get('vin', [])):
                if vin.get('prevout', {}).get('scriptpubkey_address') == address:
                    sig_hex = vin.get('scriptsig')
                    if not sig_hex and vin.get('witness'):
                        sig_hex = vin['witness'][0]
                    if not sig_hex: continue
                    
                    r_val, s_val = parse_der(sig_hex)
                    if r_val and s_val:
                        z_val = get_real_z(tx, vin_idx)
                        if z_val:
                            full_data.append({'r': r_val, 's': s_val, 'z': z_val, 'txid': txid, 'vin': vin_idx})
                            if len(full_data) >= max_sigs: return full_data
    return full_data

def extract_sigs_from_txids(address, txids, max_sigs=256):
    # Synchronous wrapper for legacy code
    return asyncio.run(async_extract_sigs_from_txids(address, txids, max_sigs))

def extract_sigs_with_real_z(address, max_pages=50, max_sigs=256):
    # This remains sync but uses async internally or we can make it all async
    # For now, let's keep it sync for compatibility but it's a bottleneck
    import requests
    full_data = []
    txids = []
    last_txid = None
    for _ in range(max_pages):
        url = f"https://mempool.space/api/address/{address}/txs/chain"
        if last_txid: url += f"/{last_txid}"
        r = requests.get(url, timeout=10)
        if r.status_code != 200: break
        txs = r.json()
        if not txs: break
        for tx in txs:
            for vin in tx.get('vin', []):
                if vin.get('prevout', {}).get('scriptpubkey_address') == address:
                    txids.append(tx['txid'])
                    break
            last_txid = tx['txid']
        if len(txids) >= max_sigs: break
    
    if txids:
        return extract_sigs_from_txids(address, txids, max_sigs)
    return []

if __name__ == "__main__":
    # Test with SegWit address from extract_tx_sigs_v2.py
    test_address = "bc1ql5hlr8ugqlav2ct3p0c5zwvjyarf0afgh6f5v6"
    manual_txids = ["c097a280bfed180a99d579053473408b8f0caa1c886bbc819fda65b08d590728"]
    sigs = extract_sigs_from_txids(test_address, manual_txids)
    for s in sigs:
        print(f"TX: {s['txid']} | R: {hex(s['r'])} | S: {hex(s['s'])} | Z: {hex(s['z'])}")
