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
try:
    import torch
    torch.set_num_threads(1)
except ImportError:
    pass
from datetime import datetime

# CONFIGURATION
STATUS_FILE = 'service_status.json'
SIGNAL_FILE = 'service_signal.txt'
WORKER_TYPES = ["fetcher", "scanner", "analyzer", "neural", "striker", "forensic", "bruteforce", "cluster"]
MAX_CPU_PERCENT = 70.0
MAX_RAM_PERCENT = 85.0

class AsyncCryScoutHub:
    def __init__(self):
        self.workers = {} # PID -> {process, type, started_at}
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
                # Small sleep to yield to other tasks
                await asyncio.sleep(0.1)
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
        
        for pid, info in list(self.workers.items()):
            try:
                os.kill(pid, signal.SIGTERM)
            except: pass
        
        # Give them a moment to exit
        await asyncio.sleep(2)
        
        # Force kill any survivors
        for pid, info in list(self.workers.items()):
            try:
                os.kill(pid, signal.SIGKILL)
            except: pass
        
        self.workers = {}
        # Status update happens at the very end of run()

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
        """Check all workers and restart any that are missing or PAUSE if CPU high."""
        await self.check_workers()
        
        cpu = psutil.cpu_percent()
        # Even if CPU is high, ensure the 'analyzer' and 'fetcher' are running if missing
        # because they are critical for progress.
        
        current_counts = { w: 0 for w in WORKER_TYPES }
        for pid, info in self.workers.items():
            if info["type"] in current_counts:
                current_counts[info["type"]] += 1
        
        if cpu > MAX_CPU_PERCENT:
            # Only start CRITICAL workers if missing when CPU is high
            for w_type in ["analyzer", "fetcher"]:
                if current_counts[w_type] < 1 and self.running:
                    self.log(f"CPU HIGH but restarting CRITICAL worker: {w_type}")
                    await self.start_worker(w_type)
            
            self.log(f"CPU HIGH ({cpu}%). PAUSING NON-CRITICAL WORKER MAINTENANCE.")
            await self.update_dashboard_json()
            return
            
        for w_type in WORKER_TYPES:
            if current_counts[w_type] < 1 and self.running:
                self.log(f"Restarting missing worker: {w_type}")
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
                        cursor.execute("UPDATE addresses SET analyzed = 0, neural_scanned = 0, tcg_scanned = 0 WHERE sigs_fetched = 1")
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
