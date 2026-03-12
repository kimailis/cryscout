#!/usr/bin/env python3
import os
import time
import random
from base_worker import BaseWorker
from db_manager import claim_address, release_address, get_connection
from scanner_forensic import ForensicScanner

class ForensicWorker(BaseWorker):
    def __init__(self, worker_id, task_name):
        super().__init__(worker_id, task_name)
        self.scanner = ForensicScanner()

    def process_loop(self):
        # Claim targets for forensic analysis
        addresses = claim_address(self.worker_id, stage='forensic', limit=10)
        
        if not addresses:
            self.heartbeat("Patrolling (Waiting for early targets)")
            time.sleep(30)
            return

        for addr in addresses:
            addr_short = f"{addr[:15]}..."
            self.heartbeat(f"Forensic: {addr_short}")
            self.log(f"Running forensic analysis on {addr}...")
            
            try:
                from db_manager import update_fail_att
                # 1. Check for Low Entropy Patterns
                if not self.scanner.scan_low_entropy_patterns():
                    update_fail_att(addr, 3)
                
                # 2. Check for Debian PID Vulnerability
                if not self.scanner.scan_debian_pid_expanded():
                    update_fail_att(addr, 3)
                
                # 3. Check for Milk Sad (Mersenne Twister)
                if not self.scanner.scan_milk_sad_mt():
                    update_fail_att(addr, 3)
                
                # 4. Targeted Randstorm (requires first_seen)
                conn = get_connection()
                c = conn.cursor()
                c.execute("SELECT first_seen FROM addresses WHERE address = ?", (addr,))
                row = c.fetchone()
                conn.close()
                
                if row and row[0]:
                    if not self.scanner.scan_lcg_randstorm(addr, row[0]):
                        update_fail_att(addr, 3)
                else:
                    update_fail_att(addr, 3)

                # Mark forensic stage as done for this address
                # We can reuse mark_analyzed or a custom flag if we add it
                from db_manager import mark_analyzed
                mark_analyzed(addr)
                
            except Exception as e:
                self.log(f"Forensic Error on {addr}: {e}")
                release_address(addr, self.worker_id)
            
            time.sleep(random.uniform(2, 5))

if __name__ == "__main__":
    worker_id = f"forensic_{os.getpid()}"
    ForensicWorker(worker_id, "Satoshi-Era Forensic Audit").run()
