#!/usr/bin/env python3
import os
import time
import json
import sqlite3
import subprocess
import signal
import sys
import threading
from db_manager import get_connection

# CONFIGURATION
STATUS_FILE = 'service_status.json'
SIGNAL_FILE = 'service_signal.txt'
MAX_CPU_PERCENT = 95.0
MAX_RAM_PERCENT = 95.0

# Global log buffer
log_buffer = []

def service_log(message):
    global log_buffer
    timestamp = time.strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] {message}"
    log_buffer.append(formatted_msg)
    if len(log_buffer) > 20:  # keep last 20 logs
        log_buffer.pop(0)
        
    try:
        sys.__stdout__.write(formatted_msg + "\n")
        sys.__stdout__.flush()
    except:
        pass
        
    # Immediately flush new logs into the JSON so the dashboard sees it live
    try:
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE, 'r') as f:
                status = json.load(f)
            status['logs'] = log_buffer
            with open(STATUS_FILE, 'w') as f:
                json.dump(status, f)
    except:
        pass

class PrintRedirector:
    def write(self, text):
        for line in text.split('\n'):
            line = line.strip()
            if line:
                service_log(line)
    def flush(self): pass

# Redirect prints so deep_scan and others log to the dashboard
sys.stdout = PrintRedirector()
sys.stderr = PrintRedirector()

def get_system_stats():
    cpu_usage = 0.0
    ram_usage = 0.0
    try:
        import psutil
        cpu_usage = psutil.cpu_percent(interval=0.1)
        ram_usage = psutil.virtual_memory().percent
        return cpu_usage, ram_usage
    except ImportError:
        pass
    # Fallback: Linux-specific
    try:
        load1, _, _ = os.getloadavg()
        num_cpus = os.cpu_count() or 1
        cpu_usage = (load1 / num_cpus) * 100
    except:
        pass
    try:
        with open('/proc/meminfo', 'r') as f:
            meminfo = {}
            for line in f:
                parts = line.split(':')
                if len(parts) == 2:
                    meminfo[parts[0].strip()] = int(parts[1].split()[0])
            total = meminfo.get('MemTotal', 1)
            used = total - meminfo.get('MemFree', 0) - meminfo.get('Buffers', 0) - meminfo.get('Cached', 0)
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
    try:
        with open(STATUS_FILE, 'w') as f:
            json.dump(status, f)
    except: pass

def check_stop_signal():
    if os.path.exists(SIGNAL_FILE):
        sig = ""
        with open(SIGNAL_FILE, 'r') as f:
            sig = f.read().strip()
        if sig == 'STOP':
            update_status(False, "Stopped")
            try:
                os.remove(SIGNAL_FILE)
            except: pass
            service_log("Stop signal received. Shutting down.")
            return True
    return False

def main_loop():
    service_log("Crypservice Engine Online. Background Scanner Active.")
    cycle = 0
    
    # We will loop through all available scanners indefinitely
    while True:
        if check_stop_signal(): break
        
        cpu, ram = get_system_stats()
        if cpu > MAX_CPU_PERCENT or ram > MAX_RAM_PERCENT:
            update_status(True, f"Waiting (CPU/RAM high)")
            time.sleep(10)
            continue
        
        cycle += 1
        service_log(f"=== Starting Scan Cycle {cycle} ===")
            
        try:
            # Phase 1: Vulnerability Scoring (prioritize targets)
            update_status(True, f"[Cycle {cycle}] Phase 1/9: Vulnerability Scoring")
            service_log("--- Scoring all addresses for vulnerability ---")
            try:
                from vulnerability_scorer import score_all_addresses
                score_all_addresses(top_n=30)
            except Exception as e:
                service_log(f"Scorer error: {str(e)[:60]}")
            
            if check_stop_signal(): break
            
            # Phase 2: Debian OpenSSL + Known-Vulnerable Key Scan
            if cycle <= 2:  # Only first 2 cycles (deterministic scan)
                update_status(True, f"[Cycle {cycle}] Phase 2/9: Known-Vuln Keys (Debian/Bandit)")
                service_log("--- Scanning Debian OpenSSL + Blockchain Bandit Keys ---")
                try:
                    from known_vuln_scanner import run_known_vuln_scan
                    seq_max = min(2**20 * cycle, 2**24)  # Expand sequential range
                    run_known_vuln_scan(sequential_max=seq_max)
                except Exception as e:
                    service_log(f"Known-vuln error: {str(e)[:60]}")
                
                if check_stop_signal(): break
            
            # Phase 3: Massive Brainwallet Dictionary (10M+ phrases)
            if cycle <= 1:  # Only first cycle (very long scan)
                update_status(True, f"[Cycle {cycle}] Phase 3/9: Massive Brainwallet (10M phrases)")
                service_log("--- Running Massive Brainwallet Dictionary Attack ---")
                try:
                    from massive_brainwallet import run_massive_brainwallet_scan
                    run_massive_brainwallet_scan()
                except Exception as e:
                    service_log(f"Brainwallet error: {str(e)[:60]}")
                
                if check_stop_signal(): break
            
            # Phase 4: Enhanced Scanner (7 attack vectors + brainwallet)
            update_status(True, f"[Cycle {cycle}] Phase 4/9: Enhanced 7-Attack Scan")
            service_log("--- Running Enhanced Deep Scan (7 attacks) ---")
            try:
                from cryscout_enhanced import enhanced_deep_scan
                enhanced_deep_scan(max_addresses=15, skip_fetch=False, skip_brainwallet=(cycle > 1))
            except Exception as e:
                service_log(f"Enhanced scan error: {str(e)[:60]}")
            
            if check_stop_signal(): break
            
            # Phase 5: BIP39 Seed Guesser (13K+ seeds)
            if cycle <= 2:
                update_status(True, f"[Cycle {cycle}] Phase 5/9: BIP39 Seed Guesser")
                service_log("--- Running BIP39 Seed Guesser ---")
                try:
                    from seed_guesser import run_seed_guesser
                    run_seed_guesser()
                except Exception as e:
                    service_log(f"Seed guesser error: {str(e)[:60]}")
                
                if check_stop_signal(): break
            
            # Phase 6: Weak Key & Pattern Scan (expand key range each cycle)
            update_status(True, f"[Cycle {cycle}] Phase 6/9: Weak Key Scanner")
            service_log("--- Scanning for Weak Keys ---")
            try:
                from weak_key_scanner import run_weak_key_scan
                key_range = min(500000 * cycle, 5000000)
                run_weak_key_scan(small_key_max=key_range)
            except Exception as e:
                service_log(f"Weak key error: {str(e)[:60]}")
            
            if check_stop_signal(): break
            
            # Phase 7: Cross-Address Collision Solver
            update_status(True, f"[Cycle {cycle}] Phase 7/9: Cross-Address Collisions")
            service_log("--- Solving Cross-Address Collisions ---")
            try:
                from solve_cross_collision import run as run_cross_coll
                run_cross_coll()
            except Exception as e:
                service_log(f"Collision solver error: {str(e)[:60]}")
            
            if check_stop_signal(): break
            
            # Phase 8: Expanded Signature Fetch (target high-TX addresses)
            update_status(True, f"[Cycle {cycle}] Phase 8/9: Expanded Sig Collection")
            service_log("--- Fetching signatures from high-TX addresses ---")
            try:
                from expanded_sig_fetch import fetch_expanded_sigs
                fetch_expanded_sigs(max_addresses=10)
            except Exception as e:
                service_log(f"Sig fetch error: {str(e)[:60]}")
            
            if check_stop_signal(): break
            
            # Phase 9: Original Deep Scan with API fetch on remaining
            update_status(True, f"[Cycle {cycle}] Phase 9/9: Deep Scan (API Fetch)")
            service_log("--- Running Deep Scan with API Fetch ---")
            try:
                from deep_scan import deep_scan
                deep_scan(max_addresses=10)
            except Exception as e:
                service_log(f"Deep scan error: {str(e)[:60]}")
            
            # End of full cycle
            service_log(f"=== Cycle {cycle} Complete ===")
            update_status(True, f"Cycle {cycle} Complete. Resting 30s...")
            time.sleep(30)
            
        except Exception as e:
            service_log(f"Loop Error: {str(e)[:60]}")
            time.sleep(10)

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
