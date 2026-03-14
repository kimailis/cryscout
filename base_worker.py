#!/usr/bin/env python3
import os
import time
import json
import sys
import psutil
import threading
import signal
try:
    import torch
    torch.set_num_threads(1)
except ImportError:
    pass
from datetime import datetime
from db_manager import update_worker_status, claim_address, release_address

class BaseWorker:
    def __init__(self, worker_id, task_name):
        self.worker_id = worker_id
        self.task_name = task_name
        self.running = True
        self.base_sleep = 1.0
        self.current_task = task_name
        self.heartbeat_thread = None
        self.last_activity = time.time()
        
        # Lower process priority to be a good citizen
        try:
            os.nice(15)
        except:
            pass
            
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._handle_exit)
        signal.signal(signal.SIGINT, self._handle_exit)

    def _handle_exit(self, signum, frame):
        self.log(f"Received signal {signum}. Shutting down gracefully...")
        self.running = False

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{self.worker_id}] {message}")
        sys.stdout.flush()

    def get_stats(self):
        # We use a very short interval to avoid blocking the heartbeat thread
        cpu = psutil.cpu_percent(interval=0.1)
        ram = psutil.virtual_memory().percent
        return cpu, ram

    def throttle(self, interval=0.1):
        """Dynamic sleep based on system CPU usage."""
        cpu = psutil.cpu_percent(interval=None) 
        if cpu > 95:
            delay = 5.0
        elif cpu > 90:
            delay = 2.0
        elif cpu > 85:
            delay = 1.0
        else:
            delay = 0.1
        
        if delay > 0.1:
            time.sleep(delay)

    def check_throttle(self, counter=None, interval=100):
        """Helper to be called from inside long-running loops."""
        if counter is not None and counter % interval != 0:
            return
            
        cpu = psutil.cpu_percent(interval=None)
        if cpu > 80:
            time.sleep(1.0)
        elif cpu > 75:
            time.sleep(0.5)
        elif cpu > 70:
            time.sleep(0.2)
        elif cpu > 65:
            time.sleep(0.1)

    def heartbeat(self, current_task=None):
        if current_task:
            self.current_task = current_task
            self.last_activity = time.time() # Progress made
            
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
        
        # Only update DB if we haven't been stuck for more than 5 minutes
        # If we are stuck, the hub will see the heartbeat stop updating.
        if time.time() - self.last_activity < 300:
            update_worker_status(self.worker_id, self.current_task, cpu, ram)

    def _heartbeat_loop(self):
        """Background loop to update heartbeat every 15 seconds."""
        while self.running:
            try:
                self.heartbeat()
            except Exception:
                pass
            for _ in range(15):
                if not self.running: break
                time.sleep(1)

    def run(self):
        self.log(f"Worker {self.worker_id} starting: {self.task_name}")
        
        # Start background heartbeat
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()
        
        try:
            while self.running:
                self.last_activity = time.time() # Main loop is alive
                self.throttle()
                self.process_loop()
                time.sleep(self.base_sleep)
        except KeyboardInterrupt:
            self.log("Stopping...")
        except Exception as e:
            self.log(f"Worker Error: {str(e)}")
            raise
        finally:
            self.running = False
            if self.heartbeat_thread:
                self.heartbeat_thread.join(timeout=2)

    def process_loop(self):
        """Override this in subclasses."""
        pass
