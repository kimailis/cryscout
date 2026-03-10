#!/usr/bin/env python3
import os
import time
import json
import sys
import psutil
import threading
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
        
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{self.worker_id}] {message}")
        sys.stdout.flush()

    def get_stats(self):
        # We use a very short interval to avoid blocking the heartbeat thread
        cpu = psutil.cpu_percent(interval=0.1)
        ram = psutil.virtual_memory().percent
        return cpu, ram

    def throttle(self):
        """Dynamic sleep based on system CPU usage to avoid being killed."""
        # Note: calling psutil.cpu_percent here might interfere with the heartbeat thread's call
        # but for simplicity we'll keep it.
        cpu = psutil.cpu_percent()
        if cpu > 95:
            delay = 10.0
        elif cpu > 90:
            delay = 5.0
        elif cpu > 85:
            delay = 2.0
        elif cpu > 75:
            delay = 1.0
        else:
            delay = 0.1
        
        if delay > 0.5:
            # self.log(f"Throttling: CPU {cpu}%, sleeping {delay}s")
            time.sleep(delay)

    def heartbeat(self, current_task=None):
        if current_task:
            self.current_task = current_task
        cpu, ram = self.get_stats()
        update_worker_status(self.worker_id, self.current_task, cpu, ram)

    def _heartbeat_loop(self):
        """Background loop to update heartbeat every 15 seconds."""
        while self.running:
            try:
                self.heartbeat()
            except Exception as e:
                # Don't let heartbeat errors crash the worker
                pass
            # Sleep in small increments to respond to self.running change
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
                # We still call throttle and process_loop in the main thread
                self.throttle()
                # We update the 'main' status before starting a loop
                self.process_loop()
                time.sleep(self.base_sleep)
        except KeyboardInterrupt:
            self.log("Stopping...")
        except Exception as e:
            self.log(f"Worker Error: {str(e)}")
            # No re-raise here to avoid hub restart loops if it's a transient error, 
            # but usually we want to know.
            raise
        finally:
            self.running = False
            if self.heartbeat_thread:
                self.heartbeat_thread.join(timeout=2)

    def process_loop(self):
        """Override this in subclasses."""
        pass
