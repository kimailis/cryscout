#!/usr/bin/env python3
import os
import time
import random
from base_worker import BaseWorker
from db_manager import claim_address, release_address, mark_stage_done, update_fail_att, update_fail_att_batch, release_all_addresses
from massive_brainwallet import run_massive_brainwallet_scan
from pollard_kangaroo import brute_force_range

class BruteForceWorker(BaseWorker):
    def process_loop(self):
        # 1. Try to claim targets from brainwallet stage first
        stage = 'brainwallet'
        addresses = claim_address(self.worker_id, stage=stage, limit=1000)
        
        # 2. If no brainwallet targets, try the final bruteforce stage
        if not addresses:
            stage = 'bruteforce'
            addresses = claim_address(self.worker_id, stage=stage, limit=1000)
        
        if not addresses:
            self.heartbeat("Idle (No addresses ready for brute force)")
            time.sleep(60)
            return

        self.heartbeat(f"Scanning {len(addresses)} targets ({stage})")
        self.log(f"Starting massive {stage} scan for {len(addresses)} addresses...")
        
        target_set = set(addresses)
        found = []
        try:
            # 1. Massive Brainwallet Scan (Always run as it's fast for large batches)
            self.log("Running massive brainwallet dictionary scan...")
            found.extend(run_massive_brainwallet_scan(target_set=target_set))
            
            # 2. Additional scans if we are in the deeper bruteforce stage
            if stage == 'bruteforce':
                # Weak Key & Pattern Scan
                self.log("Running weak key and pattern scan...")
                from weak_key_scanner import scan_pattern_keys, scan_android_rng, scan_small_keys, scan_vortex_harmonic_bruteforce
                found.extend(scan_pattern_keys(target_set))
                found.extend(scan_android_rng(target_set))
                
                # Vortex Harmonic Pruning
                self.log("Running Vortex Harmonic Pruning scan...")
                found.extend(scan_vortex_harmonic_bruteforce(target_set))
                
                # Seed Guesser (BIP39)
                self.log("Running seed guesser (BIP39 patterns)...")
                from seed_guesser import run_seed_guesser
                found_seeds = run_seed_guesser(target_addresses=target_set)
                for f in found_seeds:
                    found.append((f['address'], f['privkey'], f"Seed Guesser: {f['path']}"))
                
                # Sequential Brute Force for small ranges (up to 2^23)
                self.log("Running sequential small key brute force (2^23)...")
                found.extend(scan_small_keys(target_set, max_key=2**23))
            
            # Identify which addresses were recovered
            recovered_addrs = set(f[0] for f in found)
            failed_addrs = [addr for addr in addresses if addr not in recovered_addrs]
            
            # Batch update failure attempts
            if failed_addrs:
                attack_id = 5 if stage == 'brainwallet' else 8
                self.log(f"Updating failure stats (ID {attack_id}) for {len(failed_addrs)} addresses...")
                update_fail_att_batch(failed_addrs, attack_id)
            
            # Mark the specific stage as done
            for addr in addresses:
                mark_stage_done(addr, stage, self.worker_id)
            
            self.log(f"Batch of {len(addresses)} {stage} targets processed.")
                    
        except Exception as e:
            self.log(f"Error in brute force: {e}")
            for addr in addresses:
                release_address(addr, self.worker_id)
        finally:
            # Final cleanup of any lingering claims
            release_all_addresses(self.worker_id)
        
        time.sleep(5)

if __name__ == "__main__":
    worker_id = f"bruteforce_{os.getpid()}"
    BruteForceWorker(worker_id, "Massive Brute Force").run()
