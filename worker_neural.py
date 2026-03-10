#!/usr/bin/env python3
import os
import time
import random
import torch
from base_worker import BaseWorker
from db_manager import get_connection, add_finding
from nonce_neural_detector import scan_addresses_with_nn, train_model, load_model

class NeuralWorker(BaseWorker):
    def __init__(self, worker_id, task_name):
        super().__init__(worker_id, task_name)
        self.last_train_time = time.time()
        self.train_interval = 3600 * 12  # Re-train every 12 hours
        
    def process_loop(self):
        # 1. Periodic re-training
        if time.time() - self.last_train_time > self.train_interval:
            self.heartbeat("Learning (Training Model)")
            try:
                train_model(epochs=10, n_samples=20000)
                self.last_train_time = time.time()
            except Exception as e:
                self.log(f"Training error: {e}")

        # 2. Claim targets
        from db_manager import claim_address, mark_stage_done
        addresses = claim_address(self.worker_id, stage='neural', limit=10)
        
        if not addresses:
            self.heartbeat("Neural Scan: Idle/Resting")
            time.sleep(60) # Wait 1 min if no new sigs to scan
            return

        self.heartbeat(f"Neural Scan: Analyzing {len(addresses)} targets")
        self.log(f"Running neural anomaly detection on {len(addresses)} addresses...")
        
        try:
            flagged = scan_addresses_with_nn(addresses=addresses)
            
            # Mark all claimed addresses as neural_scanned = 1
            for addr in addresses:
                mark_stage_done(addr, 'neural', self.worker_id)
                
            if flagged:
                self.log(f"Neural net flagged {len(flagged)} addresses!")
            else:
                self.log("No new neural anomalies found in this batch.")
                
        except Exception as e:
            self.heartbeat("Neural Scan: ERROR")
            self.log(f"Neural scan error: {e}")
            # Release them if we failed
            from db_manager import release_address
            for addr in addresses:
                release_address(addr, self.worker_id)

        # Small delay between batches to be nice to the DB
        time.sleep(2)

if __name__ == "__main__":
    # Ensure model exists before starting
    if not os.path.exists('nonce_anomaly_model.pt'):
        print("[!] No model found. Performing initial training...")
        train_model(epochs=5, n_samples=10000)
        
    worker_id = f"neural_{os.getpid()}"
    NeuralWorker(worker_id, "Neural Anomaly Detection").run()
