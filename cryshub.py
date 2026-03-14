#!/usr/bin/env python3
import asyncio
import subprocess
import time
import os
import sqlite3
import signal
import psutil
import sys
import json
import random
try:
    import torch
    torch.set_num_threads(1)
except ImportError:
    pass
from datetime import datetime

# CONFIGURATION
STATUS_FILE = 'service_status.json'
SIGNAL_FILE = 'service_signal.txt'
WORKER_TYPES = ["fetcher", "scanner", "analyzer", "striker", "bruteforce"]
MAX_CPU_PERCENT = 98.0
MAX_RAM_PERCENT = 95.0

class AsyncCryScoutHub:
    def __init__(self):
        self.workers = {} # PID -> {process, type, started_at}
        self.running = True
        self.log_buffer = []
        self.cpu_spike_counter = 0
        
        # Register OS signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.handle_os_signal)
        signal.signal(signal.SIGTERM, self.handle_os_signal)
        
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] [HUB] {message}"
        print(formatted)
        self.log_buffer.append(formatted)
        if len(self.log_buffer) > 20:
            self.log_buffer.pop(0)
        sys.stdout.flush()

    async def get_worker_details(self):
        """Fetch detailed status for all active workers from the DB."""
        def query_db():
            conn = sqlite3.connect('cryscout.db', timeout=20)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT worker_id, task, cpu_usage, ram_usage, last_heartbeat 
                FROM worker_status 
                WHERE last_heartbeat > datetime('now', '-120 seconds')
                ORDER BY worker_id ASC
            """)
            rows = cursor.fetchall()
            conn.close()
            return rows
        
        try:
            rows = await asyncio.to_thread(query_db)
            details = []
            for row in rows:
                details.append({
                    "id": row[0], "task": row[1], "cpu": row[2], 
                    "ram": row[3], "last_seen": row[4]
                })
            return details
        except Exception as e:
            self.log(f"DB Query Error: {e}")
            return []

    async def update_dashboard_json(self):
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        worker_details = await self.get_worker_details()
        
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
        except Exception as e:
            self.log(f"JSON Write Error: {e}")

    async def start_worker(self, worker_type):
        script = f"worker_{worker_type}.py"
        try:
            p = await asyncio.create_subprocess_exec(
                sys.executable, script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )
            self.workers[p.pid] = {
                "process": p,
                "type": worker_type,
                "started_at": time.time()
            }
            self.log(f"Started {worker_type} worker (PID: {p.pid})")
            asyncio.create_task(self.read_worker_logs(p))
            return p
        except Exception as e:
            self.log(f"Failed to start {worker_type}: {e}")
            return None

    async def read_worker_logs(self, process):
        while True:
            try:
                line = await process.stdout.readline()
                if not line: break
                text = line.decode('utf-8', errors='replace').strip()
                if text:
                    # Filter out redundant heartbeat noise if desired, but for now show all
                    self.log(f"[{self.workers[process.pid]['type']}] {text}")
                # Yield to other tasks
                await asyncio.sleep(0.01)
            except:
                break

    async def check_workers(self):
        to_remove = []
        for pid, info in list(self.workers.items()):
            p = info["process"]
            if p.returncode is not None:
                self.log(f"Worker {info['type']} (PID: {pid}) exited with code {p.returncode}")
                to_remove.append(pid)
        for pid in to_remove:
            if pid in self.workers:
                del self.workers[pid]

    async def stop_all(self):
        self.log("Stopping all workers...")
        self.running = False
        
        # We need to take a copy to avoid concurrent modification issues
        worker_pids = list(self.workers.keys())
        for pid in worker_pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except: pass
        
        # Give them a moment to exit
        if worker_pids:
            await asyncio.sleep(2)
        
        # Force kill any survivors
        for pid in worker_pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except: pass
        
        self.workers = {}
        self.log("All workers stopped.")

    def handle_os_signal(self, signum, frame):
        self.log(f"Received OS signal {signum}. Shutting down...")
        self.running = False
        # The main loop will check self.running and exit

    async def handle_signals(self):
        """Check for external signals (STOP, START)."""
        if os.path.exists(SIGNAL_FILE):
            try:
                with open(SIGNAL_FILE, 'r') as f:
                    sig = f.read().strip()
                if sig == 'STOP':
                    self.log("Stop signal received. Shutting down.")
                    os.remove(SIGNAL_FILE)
                    await self.stop_all()
                    return 'STOP'
                elif sig == 'START':
                    self.log("Start/Refresh signal received. Checking all workers.")
                    os.remove(SIGNAL_FILE)
                    # Trigger worker maintenance immediately
                    await self.perform_worker_maintenance()
                    return 'START'
            except: pass
        return None

    async def perform_worker_maintenance(self):
        """Dynamic worker orchestration based on progress, priority and resource usage."""
        await self.check_workers()
        
        # Stale worker detection
        def get_active_ids():
            conn = sqlite3.connect('cryscout.db', timeout=20)
            c = conn.cursor()
            c.execute("SELECT worker_id FROM worker_status WHERE last_heartbeat > datetime('now', '-300 seconds')")
            ids = [row[0] for row in c.fetchall()]
            conn.close()
            return ids
            
        active_db_ids = await asyncio.to_thread(get_active_ids)
        
        for pid, info in list(self.workers.items()):
            # Find the worker_id (it's usually [type]_[pid])
            # But we can just check if any ID in active_db_ids contains this PID
            if not any(str(pid) in db_id for db_id in active_db_ids):
                # Worker is running but not in active_db_ids (stale)
                # Only if it has been running for at least 5 minutes
                if time.time() - info["started_at"] > 300:
                    self.log(f"Stale Worker Detected: {info['type']} (PID: {pid}) is not responding. Killing.")
                    try: os.kill(pid, signal.SIGKILL)
                    except: pass
                    if pid in self.workers: del self.workers[pid]

        cpu = psutil.cpu_percent()
        
        # Get work progress to determine priority
        def get_progress():
            conn = sqlite3.connect('cryscout.db', timeout=20)
            c = conn.cursor()
            stats = {}
            try:
                c.execute("SELECT COUNT(*) FROM addresses WHERE sigs_fetched = 0")
                stats['fetching'] = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM addresses WHERE sigs_fetched = 1 AND sigs_scanned = 0")
                stats['scanning'] = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM addresses WHERE sigs_fetched = 1 AND analyzed = 0")
                stats['analyzing'] = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM vulnerabilities")
                stats['vulnerabilities'] = c.fetchone()[0]
            except:
                pass
            conn.close()
            return stats
            
        progress = await asyncio.to_thread(get_progress)
        
        # MISSION PRIORITY LOGIC
        # 1. Fetching is critical if pool of unspent sigs is low.
        # 2. Scanning is priority if many sigs are fetched.
        # 3. Striker/Bruteforce is high priority if vulnerabilities are found.
        
        target_counts = { w: 1 for w in WORKER_TYPES } # Default 1 of each
        
        if progress.get('fetching', 0) > 100:
            target_counts['fetcher'] = 2
        if progress.get('scanning', 0) > 500:
            target_counts['scanner'] = 2
        if progress.get('analyzing', 0) > 100:
            target_counts['analyzer'] = 2
            
        current_counts = { w: 0 for w in WORKER_TYPES }
        for pid, info in self.workers.items():
            if info["type"] in current_counts:
                current_counts[info["type"]] += 1
        
        # RESOURCE ENFORCEMENT - DISABLED for Agent environment
        """
        if cpu > MAX_CPU_PERCENT:
            self.cpu_spike_counter += 1
            if self.cpu_spike_counter >= 2: # Spike persisted
                # Aggressively reduce to minimal workers
                non_critical = [pid for pid, info in self.workers.items() 
                               if info["type"] not in ["analyzer", "fetcher"]]
                if non_critical:
                    target_pid = random.choice(non_critical)
                    target_type = self.workers[target_pid]["type"]
                    self.log(f"CPU HIGH ({cpu}%). Dynamic Downscaling: Killing {target_type} (PID: {target_pid})")
                    try: os.kill(target_pid, signal.SIGTERM)
                    except: pass
                self.cpu_spike_counter = 0
            
            # If CPU is high, don't start any more workers, even if missing
            self.log(f"CPU HIGH ({cpu}%). Pausing worker expansion.")
            await self.update_dashboard_json()
            return
        """
        self.cpu_spike_counter = 0
        
        # Start missing workers if we have CPU headroom
        for w_type, target in target_counts.items():
            if current_counts[w_type] < target and self.running:
                # Special check: don't exceed a safe number of workers total if CPU > 50%
                total_workers = sum(current_counts.values())
                if cpu > 50 and total_workers >= len(WORKER_TYPES):
                    continue
                
                self.log(f"Dynamic Orchestration: Starting missing {w_type} (Target: {target}, Current: {current_counts[w_type]})")
                await self.start_worker(w_type)
        
        await self.update_dashboard_json()

    async def check_completion_cycle(self):
        """Monitor for Phase 1 completion and trigger Deep Scan (Phase 2)."""
        def query_db():
            conn = sqlite3.connect('cryscout.db', timeout=20)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM addresses WHERE sigs_fetched = 1")
            total_fetched = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM addresses WHERE analyzed = 1 AND sigs_fetched = 1")
            total_analyzed = cursor.fetchone()[0]
            conn.close()
            return total_fetched, total_analyzed

        try:
            total, analyzed = await asyncio.to_thread(query_db)
            if total > 0 and analyzed >= total:
                # Check if workers are idle
                worker_details = await self.get_worker_details()
                busy_workers = [w for w in worker_details if "idle" not in w['task'].lower() and "evolving" not in w['task'].lower() and "fetching" not in w['task'].lower()]
                
                if not busy_workers:
                    self.log("Phase 1 Complete. Initiating Deep Scan Cycle (Phase 2)...")
                    def reset_db():
                        conn = sqlite3.connect('cryscout.db', timeout=20)
                        cursor = conn.cursor()
                        # Reset scanning flags but KEEP fail_att and signatures
                        cursor.execute("UPDATE addresses SET analyzed = 0 WHERE sigs_fetched = 1")
                        conn.commit()
                        conn.close()
                    await asyncio.to_thread(reset_db)
                    self.log("Deep Scan Phase 2 active. Workers re-claiming targets.")
        except Exception as e:
            self.log(f"Cycle Check Error: {e}")

    async def run(self):
        self.log("Async CryScout Hub Online.")
        await self.update_dashboard_json()
        
        # Start initial workers
        for w_type in WORKER_TYPES:
            try:
                self.log(f"Attempting to start worker: {w_type}")
                await self.start_worker(w_type)
            except Exception as e:
                self.log(f"Error starting {w_type}: {e}")
        
        # Give a moment to initialize
        await asyncio.sleep(2)
        await self.update_dashboard_json()
        
        maintenance_counter = 0
        while self.running:
            try:
                # Signal check (every 1s)
                sig = await self.handle_signals()
                if sig == 'STOP': break
                
                # Full maintenance check every 15s (or when START signal hits)
                maintenance_counter += 1
                if maintenance_counter >= 15:
                    await self.perform_worker_maintenance()
                    maintenance_counter = 0
                
                # Check for cycle completion
                await self.check_completion_cycle()
                
                # Update dashboard every cycle anyway
                await self.update_dashboard_json()
                
                await asyncio.sleep(1)
                
            except Exception as e:
                self.log(f"Hub Main Loop Error: {e}")
                await asyncio.sleep(5)
        
        # Final cleanup
        self.running = False
        if self.workers:
            await self.stop_all()
        
        # FINAL STATUS UPDATE
        await self.update_dashboard_json()

if __name__ == "__main__":
    hub = AsyncCryScoutHub()
    try:
        asyncio.run(hub.run())
    except KeyboardInterrupt:
        pass
