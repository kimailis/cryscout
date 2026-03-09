#!/usr/bin/env python3
import os
import time
import json
import sqlite3
import subprocess
import signal
import sys
import threading
import hashlib
import ecdsa
import base58
import requests
import re
from db_manager import get_connection, add_finding

# CONFIGURATION
STATUS_FILE = 'service_status.json'
SIGNAL_FILE = 'service_signal.txt'
MAX_CPU_PERCENT = 50.0
MAX_RAM_PERCENT = 50.0

# Global log buffer
log_buffer = []

def service_log(message):
    global log_buffer
    timestamp = time.strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] {message}"
    print(formatted_msg)
    log_buffer.append(formatted_msg)
    if len(log_buffer) > 10:
        log_buffer.pop(0)

def get_system_stats():
    try:
        load1, _, _ = os.getloadavg()
        num_cpus = os.cpu_count() or 1
        cpu_usage = (load1 / num_cpus) * 100
    except:
        cpu_usage = 0.0

    ram_usage = 0.0
    try:
        with open('/proc/meminfo', 'r') as f:
            meminfo = {}
            for line in f:
                parts = line.split(':')
                if len(parts) == 2:
                    name = parts[0].strip()
                    value = parts[1].split()[0].strip()
                    meminfo[name] = int(value)
            
            total = meminfo.get('MemTotal', 1)
            free = meminfo.get('MemFree', 0)
            buffers = meminfo.get('Buffers', 0)
            cached = meminfo.get('Cached', 0)
            used = total - free - buffers - cached
            ram_usage = (used / total) * 100
    except:
        pass
    return cpu_usage, ram_usage

def update_status(is_running, current_task="Idle"):
    cpu, ram = get_system_stats()
    status = {
        "running": is_running,
        "current_task": current_task,
        "cpu_usage": round(cpu, 1),
        "ram_usage": round(ram, 1),
        "last_heartbeat": time.time(),
        "pid": os.getpid(),
        "logs": log_buffer
    }
    with open(STATUS_FILE, 'w') as f:
        json.dump(status, f)

def phrase_to_address(phrase):
    private_key_bytes = hashlib.sha256(phrase.encode('utf-8')).digest()
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key_bytes = b'\x04' + vk.to_string()
    sha256_pub = hashlib.sha256(public_key_bytes).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pub)
    hashed_pub = ripemd160.digest()
    prefixed_pub = b'\x00' + hashed_pub
    checksum = hashlib.sha256(hashlib.sha256(prefixed_pub).digest()).digest()[:4]
    address = base58.b58encode(prefixed_pub + checksum).decode('utf-8')
    return address, private_key_bytes.hex()

def get_phrase_variations(phrase):
    variations = {phrase, phrase.lower(), phrase.capitalize(), phrase.upper()}
    suffixes = ["123", "!", "2009", "1"]
    base_list = list(variations)
    for v in base_list:
        for s in suffixes:
            variations.add(v + s)
    return variations

def run_dictionary_scan(target_addresses):
    dict_file = "extended_dictionary.txt"
    if not os.path.exists(dict_file): return []
    service_log("Starting Dictionary Scan...")
    found_matches = []
    with open(dict_file, "r") as f:
        for line in f:
            base_phrase = line.strip()
            if not base_phrase or base_phrase.startswith("#"): continue
            for phrase in get_phrase_variations(base_phrase):
                addr, pk = phrase_to_address(phrase)
                if addr in target_addresses:
                    service_log(f"!!! MATCH FOUND: {addr}")
                    add_finding(addr, 'Brainwallet', details=f"Phrase: {phrase}, PK: {pk}", severity='High')
                    # Also record in recovered_keys
                    conn = get_connection()
                    cursor = conn.cursor()
                    cursor.execute("INSERT OR IGNORE INTO recovered_keys (address, privkey_hex, method) VALUES (?, ?, ?)", (addr, pk, 'Brainwallet'))
                    conn.commit()
                    conn.close()
                    found_matches.append((phrase, addr, pk))
    service_log("Dictionary Scan Complete.")
    return found_matches

def find_lattice_targets(address):
    url = f"https://mempool.space/api/address/{address}/txs"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            txs = resp.json()
            sigs_count = 0
            for tx in txs:
                for vin in tx.get('vin', []):
                    if vin.get('scriptsig') or vin.get('witness'):
                        sigs_count += 1
            if sigs_count >= 2:
                service_log(f"Lattice Target Found: {address} ({sigs_count} sigs)")
                add_finding(address, 'Lattice Target', details=f"Signatures count: {sigs_count}", severity='Medium')
                return True, sigs_count
    except Exception as e:
        service_log(f"API Error ({address}): {str(e)[:20]}")
    return False, 0

def run_analysis_task(address, target_addresses=None):
    try:
        from nonce_bias_detector import detect_bias
        service_log(f"Analyzing {address[:12]}...")
        is_biased = detect_bias(address)
        is_lattice_target, sig_count = find_lattice_targets(address)
        if target_addresses: run_dictionary_scan(target_addresses)
        return True, is_biased or is_lattice_target
    except Exception as e:
        service_log(f"Task Error: {str(e)[:30]}")
        return False, False

def main_loop():
    service_log("Crypservice Engine Online.")
    dict_checked = False
    
    while True:
        if os.path.exists(SIGNAL_FILE):
            with open(SIGNAL_FILE, 'r') as f:
                sig = f.read().strip()
                if sig == 'STOP':
                    update_status(False, "Stopped")
                    os.remove(SIGNAL_FILE)
                    service_log("Stop signal received. Shutting down.")
                    break

        cpu, ram = get_system_stats()
        if cpu > MAX_CPU_PERCENT or ram > MAX_RAM_PERCENT:
            update_status(True, f"Waiting (Resources high)")
            time.sleep(10)
            continue

        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT address FROM addresses")
            target_addresses = set(row[0] for row in cursor.fetchall())
            
            cursor.execute("SELECT address FROM addresses WHERE analyzed = 0 LIMIT 1")
            row = cursor.fetchone()
            
            if row:
                target_address = row[0]
                update_status(True, f"Analyzing {target_address[:15]}...")
                
                success, found_something = run_analysis_task(target_address, target_addresses if not dict_checked else None)
                dict_checked = True 
                
                if success:
                    cursor.execute("UPDATE addresses SET analyzed = 1 WHERE address = ?", (target_address,))
                    if found_something:
                        cursor.execute('''
                        UPDATE addresses 
                        SET potential_weakness = ? 
                        WHERE address = ? AND (potential_weakness IS NULL OR potential_weakness = 'None Identified')
                        ''', ("High Analysis Priority (Lattice/Bias)", target_address))
                    conn.commit()
                conn.close()
                work_todo_empty = False
            else:
                conn.close()
                if not dict_checked:
                    update_status(True, "Running Dictionary Scan")
                    run_dictionary_scan(target_addresses)
                    dict_checked = True
                update_status(True, "Idle (All addresses analyzed)")
                work_todo_empty = True
        except Exception as e:
            service_log(f"Loop Error: {str(e)[:30]}")
            time.sleep(5)
            work_todo_empty = True
        
        update_status(True, "Idle" if work_todo_empty else "Working")
        time.sleep(1)

if __name__ == "__main__":
    if os.path.exists(STATUS_FILE):
        try:
            with open(STATUS_FILE, 'r') as f:
                old_status = json.load(f)
                if old_status.get('running') and (time.time() - old_status.get('last_heartbeat', 0)) < 10:
                    sys.exit(0)
        except: pass
    try: main_loop()
    except KeyboardInterrupt: update_status(False, "Interrupted")
