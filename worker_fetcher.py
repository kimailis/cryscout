#!/usr/bin/env python3
import os
import time
import random
from base_worker import BaseWorker
from db_manager import claim_address, release_address, get_connection, mark_stage_done
from cryscout_enhanced import extract_sigs_for_address_enhanced

class FetcherWorker(BaseWorker):
    def process_loop(self):
        addresses = claim_address(self.worker_id, stage='fetching', limit=3)
        if not addresses:
            self.heartbeat("Idle (Waiting for targets)")
            time.sleep(10)
            return

        for addr in addresses:
            self.heartbeat(f"Fetching: {addr[:15]}...")
            self.log(f"Fetching signatures for {addr}...")
            
            # Use existing logic from cryscout_enhanced
            try:
                # Check existing sig count
                conn = get_connection()
                c = conn.cursor()
                c.execute("SELECT COUNT(*) FROM signatures WHERE address = ?", (addr,))
                existing_sigs = c.fetchone()[0]
                conn.close()
                
                extract_sigs_for_address_enhanced(addr, existing_sigs=existing_sigs, max_sigs=256)
                mark_stage_done(addr, 'fetching', self.worker_id)
            except Exception as e:
                self.log(f"Error fetching {addr}: {e}")
                release_address(addr, self.worker_id)
            
            # Small random delay to avoid hitting APIs too hard
            time.sleep(random.uniform(1, 3))

if __name__ == "__main__":
    worker_id = f"fetcher_{os.getpid()}"
    FetcherWorker(worker_id, "Sig Fetching").run()
