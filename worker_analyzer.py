#!/usr/bin/env python3
import os
import time
import random
from base_worker import BaseWorker
from db_manager import claim_address, release_address, get_connection
from cryscout_enhanced import run_lattice_attacks_enhanced, check_r_reuse_strict
from deep_scan import run_algebraic_attacks

class AnalyzerWorker(BaseWorker):
    def process_loop(self):
        # Analyzer needs addresses that HAVE signatures
        conn = get_connection()
        c = conn.cursor()
        c.execute("""
            SELECT a.address FROM addresses a
            JOIN (SELECT address, COUNT(*) as sig_count FROM signatures GROUP BY address) s
                ON a.address = s.address
            WHERE a.analyzed = 0 
            AND (a.processing_by IS NULL OR a.processing_since < datetime('now', '-30 minutes'))
            AND s.sig_count >= 2
            ORDER BY a.current_balance DESC
            LIMIT 1
        """)
        row = c.fetchone()
        conn.close()
        
        if not row:
            self.heartbeat("Idle (Waiting for sigs)")
            time.sleep(10)
            return

        addr = row[0]
        # Claim it
        conn = get_connection()
        c = conn.cursor()
        c.execute("UPDATE addresses SET processing_by = ?, processing_since = CURRENT_TIMESTAMP WHERE address = ?", (self.worker_id, addr))
        conn.commit()
        conn.close()

        self.heartbeat(f"Analyzing: {addr[:15]}...")
        self.log(f"Starting analysis for {addr}...")
        
        try:
            found = False
            # Check R-reuse (fast)
            if check_r_reuse_strict(addr):
                self.log(f"!!! SUCCESS: R-reuse found for {addr}")
                found = True
            
            # Lattice attack
            if not found and run_lattice_attacks_enhanced(addr):
                self.log(f"!!! SUCCESS: Lattice key found for {addr}")
                found = True
            
            # Algebraic attacks
            if not found and run_algebraic_attacks(addr):
                self.log(f"!!! SUCCESS: Algebraic key found for {addr}")
                found = True
            
            # Done with this address
            release_address(addr, self.worker_id, mark_done=True)
            self.log(f"Finished analysis for {addr}")
        except Exception as e:
            self.log(f"Error analyzing {addr}: {e}")
            release_address(addr, self.worker_id)
        
        time.sleep(1)

if __name__ == "__main__":
    worker_id = f"analyzer_{os.getpid()}"
    AnalyzerWorker(worker_id, "Lattice Analysis").run()
