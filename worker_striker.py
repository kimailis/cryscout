#!/usr/bin/env python3
import os
import time
import random
from base_worker import BaseWorker
from db_manager import claim_address, release_address, get_connection
from cryscout_enhanced import run_lattice_attacks_enhanced
from advanced_lattice import run_advanced_lattice
from pollard_kangaroo import run_kangaroo_scan

class StrikerWorker(BaseWorker):
    def process_loop(self):
        # The Striker ONLY targets addresses with known vulnerabilities/anomalies
        conn = get_connection()
        c = conn.cursor()
        c.execute("""
            SELECT DISTINCT v.address FROM vulnerabilities v
            JOIN addresses a ON v.address = a.address
            WHERE (a.processing_by IS NULL OR a.processing_since < datetime('now', '-1 hour'))
            AND a.status != 'Compromised'
            ORDER BY 
                CASE v.severity 
                    WHEN 'Critical' THEN 1 
                    WHEN 'High' THEN 2 
                    ELSE 3 
                END ASC,
                a.current_balance DESC
            LIMIT 1
        """)
        row = c.fetchone()
        conn.close()
        
        if not row:
            self.heartbeat("Patrolling (Waiting for flags)")
            time.sleep(20)
            return

        addr = row[0]
        # Claim it exclusively for striking
        conn = get_connection()
        c = conn.cursor()
        c.execute("UPDATE addresses SET processing_by = ?, processing_since = CURRENT_TIMESTAMP WHERE address = ?", (self.worker_id, addr))
        conn.commit()
        conn.close()

        addr_short = f"{addr[:10]}..."
        self.heartbeat(f"STRIKING: {addr_short} (BKZ)")
        self.log(f"!!! STARTING INTENSIVE STRIKE ON HIGH-PROBABILITY TARGET: {addr} !!!")
        
        try:
            # 1. Advanced BKZ Lattice Reduction (More powerful than standard HNP)
            self.log(f"Phase 1: Running BKZ Lattice Reduction on {addr}")
            if run_advanced_lattice(max_addresses=1, target_address=addr):
                self.log(f"$$$ SUCCESS! Private key recovered for {addr} via BKZ $$$")
                release_address(addr, self.worker_id, mark_done=True)
                return

            # 2. Pollard's Kangaroo (Bounded ECDLP search - for very small/biased ranges)
            self.heartbeat(f"STRIKING: {addr_short} (Kangaroo)")
            self.log(f"Phase 2: Running Pollard's Kangaroo bounded search on {addr}")
            if run_kangaroo_scan(max_addresses=1, target_address=addr):
                self.log(f"$$$ SUCCESS! Private key recovered for {addr} via Kangaroo $$$")
                release_address(addr, self.worker_id, mark_done=True)
                return
            
            # 3. Enhanced Lattice (Standard) as a fallback
            self.heartbeat(f"STRIKING: {addr_short} (Lattice)")
            if run_lattice_attacks_enhanced(addr):
                self.log(f"$$$ SUCCESS! Private key recovered for {addr} via Enhanced Lattice $$$")
                release_address(addr, self.worker_id, mark_done=True)
                return

            # If we reach here, intensive strike failed for now
            self.heartbeat(f"Strike failed: {addr_short}")
            self.log(f"Strike complete for {addr}. No key recovered yet.")
            release_address(addr, self.worker_id)
            
        except Exception as e:
            self.log(f"Strike error on {addr}: {e}")
            release_address(addr, self.worker_id)
        
        time.sleep(5)

if __name__ == "__main__":
    worker_id = f"striker_{os.getpid()}"
    StrikerWorker(worker_id, "Intensive High-Value Strike").run()
