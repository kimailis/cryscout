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
MAX_CPU_PERCENT = 50.0
MAX_RAM_PERCENT = 50.0

# Global log buffer
log_buffer = []

def service_log(message):
    global log_buffer
    timestamp = time.strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] {message}"
    log_buffer.append(formatted_msg)
    if len(log_buffer) > 20:  # keep last 20 logs
        log_buffer.pop(0)

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
        with open(SIGNAL_FILE, 'r') as f:
            sig = f.read().strip()
            if sig == 'STOP':
                update_status(False, "Stopped")
                os.remove(SIGNAL_FILE)
                service_log("Stop signal received. Shutting down.")
                return True
    return False

def main_loop():
    service_log("Crypservice Engine Online. Background Scanner Active.")
    
    # We will loop through the different intensive scanners indefinitely
    while True:
        if check_stop_signal(): break
        
        cpu, ram = get_system_stats()
        if cpu > MAX_CPU_PERCENT or ram > MAX_RAM_PERCENT:
            update_status(True, f"Waiting (CPU/RAM high)")
            time.sleep(10)
            continue
            
        try:
            # 1. Weak Key & Brainwallet Scan
            update_status(True, "Scanning for Weak Keys & Brainwallets")
            service_log("--- Starting Weak Key Scan ---")
            from weak_key_scanner import run_weak_key_scan
            run_weak_key_scan(small_key_max=500000) # Scan up to 500k as part of cycle
            
            if check_stop_signal(): break
            
            # 2. Cross-Address Collision Solver
            update_status(True, "Solving Cross-Address Collisions")
            service_log("--- Starting Cross-Address Collision Scan ---")
            from solve_cross_collision import run as run_cross_coll
            run_cross_coll()
            
            if check_stop_signal(): break
            
            # 3. Deep Scan (API Fetch, R-Reuse, Lattice, Polynonce, Algebraic)
            update_status(True, "Running Deep Scan & Advanced Attacks")
            service_log("--- Starting Deep Scan (Targeted) ---")
            from deep_scan import deep_scan
            # Analyze top 10 un-analyzed or highest value per loop to keep it moving
            deep_scan(max_addresses=10)
            
            # End of full cycle wait
            update_status(True, "Cycle Complete. Resting...")
            time.sleep(10)
            
        except Exception as e:
            service_log(f"Loop Error: {str(e)[:50]}")
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
