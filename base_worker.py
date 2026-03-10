#!/usr/bin/env python3
import os
import time
import json
import sys
import psutil
from datetime import datetime
from db_manager import update_worker_status, claim_address, release_address

class BaseWorker:
    def __init__(self, worker_id, task_name):
        self.worker_id = worker_id
        self.task_name = task_name
        self.running = True
        self.base_sleep = 1.0
        
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{self.worker_id}] {message}")
        sys.stdout.flush()

    def get_stats(self):
        cpu = psutil.cpu_percent(interval=0.1)
        ram = psutil.virtual_memory().percent
        return cpu, ram

    def throttle(self):
        """Dynamic sleep based on system CPU usage to avoid being killed."""
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
        cpu, ram = self.get_stats()
        update_worker_status(self.worker_id, current_task or self.task_name, cpu, ram)

    def run(self):
        self.log(f"Worker {self.worker_id} starting: {self.task_name}")
        try:
            while self.running:
                self.throttle()
                self.heartbeat()
                self.process_loop()
                time.sleep(self.base_sleep)
        except KeyboardInterrupt:
            self.log("Stopping...")
        except Exception as e:
            self.log(f"Worker Error: {str(e)}")
            raise

    def process_loop(self):
        """Override this in subclasses."""
        pass
