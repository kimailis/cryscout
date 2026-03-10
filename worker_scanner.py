#!/usr/bin/env python3
import os
import time
import random
from base_worker import BaseWorker
from db_manager import claim_address, release_address, get_connection
from cryscout_enhanced import check_known_weak_nonces, try_related_nonce
from weak_key_scanner import run_weak_key_scan
from historical_vuln_scanner import run_historical_scans

class ScannerWorker(BaseWorker):
    def process_loop(self):
        # Scanner picks any unanalyzed address
        addresses = claim_address(self.worker_id, limit=1)
        if not addresses:
            self.heartbeat("Idle (Waiting for targets)")
            time.sleep(10)
            return

        for addr in addresses:
            self.heartbeat(f"Scanning: {addr[:15]}...")
            self.log(f"Scanning {addr} for weak keys/patterns...")
            
            try:
                # 1. Historical Vulnerability Scans (Trust Wallet, Android, BIP32, Whisper)
                self.log(f"Running historical vulnerability scans on {addr}")
                if run_historical_scans(addr):
                    self.log(f"!!! SUCCESS: Historical vulnerability found key for {addr}")

                # 2. Check known weak nonces (fast)
                if check_known_weak_nonces(addr):
                    self.log(f"!!! SUCCESS: Weak nonce found for {addr}")
                
                # 3. Check related nonces
                if try_related_nonce(addr):
                    self.log(f"!!! SUCCESS: Related nonce found for {addr}")
                
                # 4. Weak key scan (sequential range)
                # We'll just do a small check here as part of the worker
                # Full scan is done by the main weak_key_scanner script
                
                # Release it - analyzer might still want to look at sigs if they exist
                # But if we found a key, it's already marked in recovered_keys
                release_address(addr, self.worker_id)
            except Exception as e:
                self.log(f"Error scanning {addr}: {e}")
                release_address(addr, self.worker_id)
            
            time.sleep(2)

if __name__ == "__main__":
    worker_id = f"scanner_{os.getpid()}"
    ScannerWorker(worker_id, "Weak Pattern Scan").run()
