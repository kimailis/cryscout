#!/usr/bin/env python3
import os
import time
from base_worker import BaseWorker
from db_manager import claim_address, release_address, mark_stage_done, update_fail_att, get_full_signatures, add_finding
from vortex_math_analyzer import scan_vortex_anomalies

class VortexWorker(BaseWorker):
    def process_loop(self):
        # Claim targets
        stage = 'vortex'
        addresses = claim_address(self.worker_id, stage=stage, limit=20)
        
        if not addresses:
            self.heartbeat(f"Idle (No addresses ready for {stage})")
            time.sleep(15)
            return

        self.heartbeat(f"Scanning {len(addresses)} targets ({stage})")
        self.log(f"Starting {stage} analysis for {len(addresses)} addresses...")
        
        try:
            # Prepare data for analysis
            sigs_data_map = {}
            for addr in addresses:
                sigs = get_full_signatures(addr)
                sigs_data_map[addr] = sigs
                
            self.log("Running Vortex Harmonic Pruning and Spin-Glass IE Binding analysis...")
            anomalies = scan_vortex_anomalies(addresses, sigs_data_map)
            
            flagged_set = set(f['address'] for f in anomalies) if anomalies else set()
            
            # Record findings
            for anomaly in anomalies:
                add_finding(
                    anomaly['address'],
                    anomaly['type'],
                    None,
                    anomaly['details'],
                    anomaly['severity']
                )

            # Mark all claimed addresses as scanned
            for addr in addresses:
                mark_stage_done(addr, stage, self.worker_id)
                if addr not in flagged_set:
                    # Increment failure count for this stage (we'll assign ID 10 to vortex)
                    update_fail_att(addr, 10)
                
            if anomalies:
                self.log(f"Vortex analyzer flagged {len(anomalies)} anomalies!")
            else:
                self.log("No new vortex/topological anomalies found in this batch.")
                    
        except Exception as e:
            self.log(f"Error in {stage} analysis: {e}")
            for addr in addresses:
                release_address(addr, self.worker_id)
        
        time.sleep(2)

if __name__ == "__main__":
    worker_id = f"vortex_{os.getpid()}"
    VortexWorker(worker_id, "Vortex & Spin-Glass Analyzer").run()
