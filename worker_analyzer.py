#!/usr/bin/env python3
import os
import time
import random
from base_worker import BaseWorker
from db_manager import claim_address, release_address, get_connection, mark_stage_done
from cryscout_enhanced import run_lattice_attacks_enhanced, check_r_reuse_strict
from deep_scan import run_algebraic_attacks

class AnalyzerWorker(BaseWorker):
    def process_loop(self):
        # Analyzer needs addresses that HAVE signatures and haven't been analyzed
        extra_filter = "a.address IN (SELECT address FROM signatures GROUP BY address HAVING COUNT(*) >= 1)"
        addresses = claim_address(self.worker_id, stage='analyzing', limit=1, extra_filter=extra_filter)
        
        if not addresses:
            self.heartbeat("Idle (Waiting for sigs)")
            time.sleep(10)
            return

        addr = addresses[0]
        self.heartbeat(f"Analyzing: {addr[:15]}...")
        self.log(f"Starting analysis for {addr}...")
        
        try:
            found = False
            self.check_throttle()
            
            # Check R-reuse (fast)
            if check_r_reuse_strict(addr):
                self.log(f"!!! SUCCESS: R-reuse found for {addr}")
                found = True
            else:
                from db_manager import update_fail_att
                update_fail_att(addr, 2)            
            
            self.check_throttle()
            
            # 2. Lattice attack
            if not found and run_lattice_attacks_enhanced(addr):
                self.log(f"!!! SUCCESS: Lattice key found for {addr}")
                found = True
            elif not found:
                from db_manager import update_fail_att
                update_fail_att(addr, 2)            
            
            self.check_throttle()
            
            # 2.5 Deep LSB Bias Detection (NEW)
            if not found:
                try:
                    from check_lsb_system import check_lsb_system
                    from db_manager import get_signatures, add_finding
                    sigs = get_signatures(addr)
                    if len(sigs) >= 5:
                        self.log(f"Running deep LSB bias detection on {addr}...")
                        bias_results = check_lsb_system(sigs, max_bits=20)
                        if bias_results:
                            # Use the best result (highest bits or best ratio)
                            best = max(bias_results, key=lambda x: x['bits'])
                            self.log(f"!!! DEEP BIAS FOUND for {addr}: {best['bits']} bits, d_mod={best['d_mod']}")
                            add_finding(addr, 'Deep LSB Bias', details=best, severity='High')
                except Exception as e:
                    self.log(f"Deep bias scan error for {addr}: {e}")

            self.check_throttle()
            
            # 3. Algebraic attacks
            if not found and run_algebraic_attacks(addr):
                self.log(f"!!! SUCCESS: Algebraic key found for {addr}")
                found = True
            elif not found:
                from db_manager import update_fail_att
                update_fail_att(addr, 2)            
            
            # Done with this address
            mark_stage_done(addr, 'analyzing', self.worker_id)
            self.log(f"Finished analysis for {addr}")
        except Exception as e:
            self.log(f"Error analyzing {addr}: {e}")
            release_address(addr, self.worker_id)
        
        time.sleep(1)

if __name__ == "__main__":
    worker_id = f"analyzer_{os.getpid()}"
    AnalyzerWorker(worker_id, "Lattice Analysis").run()
