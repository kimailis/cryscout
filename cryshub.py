#!/usr/bin/env python3
import subprocess
import time
import os
import sqlite3
import signal
import psutil
import sys
import json
from datetime import datetime

# CONFIGURATION
STATUS_FILE = 'service_status.json'
SIGNAL_FILE = 'service_signal.txt'
MAX_WORKERS = 4
MAX_CPU_PERCENT = 85.0
MAX_RAM_PERCENT = 85.0

class CryScoutHub:
    def __init__(self):
        self.workers = {} # PID -> {process, type, started_at, last_log}
        self.running = True
        self.log_buffer = []
        
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] [HUB] {message}"
        print(formatted)
        self.log_buffer.append(formatted)
        if len(self.log_buffer) > 20:
            self.log_buffer.pop(0)
        sys.stdout.flush()

    def get_worker_details(self):
        """Fetch detailed status for all active workers from the DB."""
        details = []
        try:
            # Use the same connection helper as others if possible, but keep it simple
            conn = sqlite3.connect('cryscout.db', timeout=20)
            cursor = conn.cursor()
            # Get workers active in the last 120 seconds (be more generous)
            cursor.execute("""
                SELECT worker_id, task, cpu_usage, ram_usage, last_heartbeat 
                FROM worker_status 
                WHERE last_heartbeat > datetime('now', '-120 seconds')
                ORDER BY worker_id ASC
            """)
            rows = cursor.fetchall()
            for row in rows:
                details.append({
                    "id": row[0],
                    "task": row[1],
                    "cpu": row[2],
                    "ram": row[3],
                    "last_seen": row[4]
                })
            conn.close()
        except Exception as e:
            # We print directly to stdout here to avoid any chance of recursion in log()
            print(f"Error fetching worker details: {e}")
        return details

    def update_dashboard_json(self, cpu_val=None):
        cpu = cpu_val if cpu_val is not None else psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        
        # Aggregate worker statuses
        worker_details = self.get_worker_details()
        
        status = {
            "running": self.running,
            "current_task": f"Hub active: {len(worker_details)} workers",
            "cpu_usage": round(cpu, 1),
            "ram_usage": round(ram, 1),
            "last_heartbeat": time.time(),
            "pid": os.getpid(),
            "logs": self.log_buffer,
            "worker_count": len(worker_details),
            "workers_detailed": worker_details
        }
        try:
            with open(STATUS_FILE, 'w') as f:
                json.dump(status, f)
        except: pass

    def start_worker(self, worker_type):
        script = f"worker_{worker_type}.py"
        try:
            # Run in a way that doesn't capture output to avoid filling pipe buffers
            # but allows us to see logs in the hub's stdout if we want, or redirect to files.
            p = subprocess.Popen([sys.executable, script], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.STDOUT,
                                text=True,
                                bufsize=1)
            self.workers[p.pid] = {
                "process": p,
                "type": worker_type,
                "started_at": time.time()
            }
            self.log(f"Started {worker_type} worker (PID: {p.pid})")
            return p
        except Exception as e:
            self.log(f"Failed to start {worker_type}: {e}")
            return None

    def check_workers(self):
        to_remove = []
        for pid, info in self.workers.items():
            p = info["process"]
            if p.poll() is not None:
                # Process died
                out, _ = p.communicate()
                self.log(f"Worker {info['type']} (PID: {pid}) exited with code {p.returncode}")
                if out:
                    self.log(f"Last logs from {pid}: {out.splitlines()[-3:] if out else 'none'}")
                to_remove.append(pid)
        
        for pid in to_remove:
            del self.workers[pid]

    def stop_all(self):
        self.log("Stopping all workers...")
        for pid, info in self.workers.items():
            try:
                os.kill(pid, signal.SIGTERM)
            except:
                pass
        self.running = False

    def check_stop_signal(self):
        if os.path.exists(SIGNAL_FILE):
            try:
                with open(SIGNAL_FILE, 'r') as f:
                    sig = f.read().strip()
                if sig == 'STOP':
                    self.log("Stop signal received from dashboard. Shutting down.")
                    os.remove(SIGNAL_FILE)
                    self.stop_all()
                    return True
            except: pass
        return False

    def run(self):
        self.log("CryScout Hub Online. Managing parallel services.")
        
        # Initial workers
        self.start_worker("fetcher")
        self.start_worker("scanner")
        self.start_worker("analyzer")
        self.start_worker("neural")
        self.start_worker("striker")
        
        while self.running:
            try:
                if self.check_stop_signal(): break
                self.check_workers()
                
                cpu = psutil.cpu_percent(interval=1)
                ram = psutil.virtual_memory().percent
                
                # Update dashboard every loop to keep heartbeat alive
                self.update_dashboard_json(cpu_val=cpu)
                
                # Resource management logic
                if cpu > MAX_CPU_PERCENT or ram > MAX_RAM_PERCENT:
                    if len(self.workers) > 1:
                        # Striker is most intensive, followed by analyzer and neural
                        targets = [pid for pid, info in self.workers.items() if info["type"] in ["striker", "analyzer", "neural"]]
                        if targets:
                            pid = targets[0]
                            self.log(f"Resource pressure (CPU:{cpu}%, RAM:{ram}%). Killing {self.workers[pid]['type']} {pid}.")
                            os.kill(pid, signal.SIGTERM)
                
                # Maintain minimum workers
                counts = { "fetcher": 0, "analyzer": 0, "scanner": 0, "neural": 0, "striker": 0 }
                for pid, info in self.workers.items():
                    counts[info["type"]] += 1
                
                if self.running:
                    if counts["fetcher"] < 1: self.start_worker("fetcher")
                    if counts["scanner"] < 1: self.start_worker("scanner")
                    if counts["analyzer"] < 1 and cpu < (MAX_CPU_PERCENT - 20):
                        self.start_worker("analyzer")
                    if counts["neural"] < 1 and ram < (MAX_RAM_PERCENT - 20):
                        self.start_worker("neural")
                    if counts["striker"] < 1 and cpu < (MAX_CPU_PERCENT - 40):
                        self.start_worker("striker")
                
                time.sleep(2)
                
            except KeyboardInterrupt:
                self.stop_all()
                break
            except Exception as e:
                self.log(f"Hub Error: {e}")
                time.sleep(5)

if __name__ == "__main__":
    hub = CryScoutHub()
    try:
        hub.run()
    except KeyboardInterrupt:
        hub.stop_all()
