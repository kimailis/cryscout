#!/usr/bin/env python3
import os
import time
import random
import threading
import torch
from base_worker import BaseWorker
from db_manager import get_connection, add_finding
from nonce_neural_detector import scan_addresses_with_nn, train_model, train_lstm_model, load_models

class NeuralWorker(BaseWorker):
    def __init__(self, worker_id, task_name):
        super().__init__(worker_id, task_name)
        self.training_thread = None
        self.is_training = False
        self.training_cycle_count = 0
        
    def start_training_thread(self):
        self.training_thread = threading.Thread(target=self._continuous_training_loop, daemon=True)
        self.training_thread.start()
        
    def _continuous_training_loop(self):
        self.log("Starting continuous evolutionary training thread...")
        while self.running:
            self.is_training = True
            try:
                # Load current models to fine-tune them
                ff_model, lstm_model = load_models()
                
                # Small training batches to adapt to mutations continuously
                train_model(epochs=3, n_samples=15000, model=ff_model)
                train_lstm_model(epochs=3, n_samples=8000, model=lstm_model)
                
                self.training_cycle_count += 1
                self.log(f"Completed evolutionary training cycle {self.training_cycle_count}")
            except Exception as e:
                self.log(f"Training error: {e}")
            self.is_training = False
            
            # Briefly yield to allow the scanner to take priority if needed
            for _ in range(15):
                if not self.running: break
                time.sleep(1)

    def run(self):
        # Override run to launch the background training thread
        self.start_training_thread()
        super().run()
        
    def process_loop(self):
        # Claim targets
        from db_manager import claim_address, mark_stage_done
        addresses = claim_address(self.worker_id, stage='neural', limit=10)
        
        if not addresses:
            # Update heartbeat to reflect that it is currently evolving models
            status_msg = f"Evolving Models (Cycle {self.training_cycle_count})" if self.is_training else "Neural Scan: Idle/Resting"
            self.heartbeat(status_msg)
            time.sleep(15) 
            return

        self.heartbeat(f"Neural Scan: Analyzing {len(addresses)} targets")
        self.log(f"Running neural anomaly detection on {len(addresses)} addresses...")
        
        try:
            flagged = scan_addresses_with_nn(addresses=addresses)
            flagged_set = set(f['address'] for f in flagged) if flagged else set()
            
            # Mark all claimed addresses as neural_scanned = 1
            for addr in addresses:
                mark_stage_done(addr, 'neural', self.worker_id)
                if addr not in flagged_set:
                    from db_manager import update_fail_att
                    update_fail_att(addr, 7)
                
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

        time.sleep(2)

if __name__ == "__main__":
    # Ensure models exist before starting
    if not os.path.exists('nonce_anomaly_model.pt'):
        print("[!] No FFNN model found. Performing initial training...")
        train_model(epochs=5, n_samples=10000)
    if not os.path.exists('spectral_bias_lstm.pt'):
        print("[!] No LSTM model found. Performing initial training...")
        train_lstm_model(epochs=5, n_samples=5000)
        
    worker_id = f"neural_{os.getpid()}"
    NeuralWorker(worker_id, "Neural Anomaly Detection").run()
