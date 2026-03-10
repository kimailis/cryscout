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
        self.train_interval = 3600 * 6  # Re-train every 6 hours to "learn" new patterns
        
    def process_loop(self):
        # 1. Check if we need to re-train (learning phase)
        if time.time() - self.last_train_time > self.train_interval:
            self.heartbeat("Learning (Training Model)")
            self.log("Starting periodic re-training...")
            try:
                # We can increase samples over time or use different seeds
                train_model(epochs=10, n_samples=20000)
                self.last_train_time = time.time()
                self.log("Re-training complete.")
            except Exception as e:
                self.log(f"Training error: {e}")

        # 2. Scanning phase
        self.heartbeat("Neural Scan: Initializing")
        self.log("Scanning addresses for neural anomalies...")
        try:
            # We'll simulate a bit more granularity by splitting the scan if we could, 
            # but for now we'll just update the heartbeat to be more descriptive
            self.heartbeat("Neural Scan: Analyzing 20 targets")
            flagged = scan_addresses_with_nn(max_addresses=20)
            if flagged:
                self.heartbeat(f"Neural Scan: Found {len(flagged)} FLAGGED!")
                self.log(f"Neural net flagged {len(flagged)} addresses!")
                for f in flagged:
                    self.log(f"  Flagged: {f['address'][:20]}... P={f['probability']:.4f}")
            else:
                self.heartbeat("Neural Scan: No anomalies")
                self.log("No new neural anomalies found.")
        except Exception as e:
            self.heartbeat("Neural Scan: ERROR")
            self.log(f"Neural scan error: {e}")

        # Neural scanning is heavy, so we wait longer between passes
        self.heartbeat("Neural Scan: Idle/Resting")
        time.sleep(300) # Scan every 5 minutes

if __name__ == "__main__":
    # Ensure model exists before starting
    if not os.path.exists('nonce_anomaly_model.pt'):
        print("[!] No model found. Performing initial training...")
        train_model(epochs=5, n_samples=10000)
        
    worker_id = f"neural_{os.getpid()}"
    NeuralWorker(worker_id, "Neural Anomaly Detection").run()
