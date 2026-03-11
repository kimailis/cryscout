#!/usr/bin/env python3
import os
import time
from base_worker import BaseWorker
from db_manager import claim_address, mark_stage_done, release_address, get_connection, update_fail_att
from tcg_norm_analyzer import tcg_collision_search, generate_mutated_tcg_params

class TCGWorker(BaseWorker):
    def __init__(self, worker_id, task_name):
        super().__init__(worker_id, task_name)
        self.evolution_cycle = 0
        
    def process_loop(self):
        # 1. Try to claim fresh targets for TCG stage first
        addresses = claim_address(self.worker_id, stage='tcg', limit=20)
        is_evolutionary_run = False
        
        if not addresses:
            # 2. Evolutionary Mode: If caught up, pick random addresses to re-evaluate with mutated norms
            self.evolution_cycle += 1
            self.heartbeat(f"Evolving: Cycle {self.evolution_cycle}")
            conn = get_connection()
            c = conn.cursor()
            # Claim random addresses that already have signatures
            c.execute('''
                SELECT address FROM addresses 
                WHERE sigs_fetched = 1 AND (processing_by IS NULL OR processing_by = ?)
                ORDER BY RANDOM() LIMIT 20
            ''', (self.worker_id,))
            addresses = [row[0] for row in c.fetchall()]
            
            # Lock them temporarily for this worker
            if addresses:
                placeholders = ', '.join(['?'] * len(addresses))
                c.execute(f"UPDATE addresses SET processing_by = ? WHERE address IN ({placeholders})", [self.worker_id] + addresses)
                conn.commit()
                
            conn.close()
            is_evolutionary_run = True
            
            if not addresses:
                self.heartbeat("TCG Scan: Idle (No signatures in DB)")
                time.sleep(30)
                return

        # Generate fresh mutated parameters for this batch to find hidden geometric collisions
        current_params = generate_mutated_tcg_params()
        status_prefix = "Evolving" if is_evolutionary_run else "Analyzing"
        self.heartbeat(f"TCG {status_prefix} {len(addresses)} targets")
        
        # Keep logs concise, just indicate mutation is active
        # self.log(f"Running mutated TCG scan... Tau={current_params['tau']:.2f}, Iota={current_params['iota']:.2f}")
        
        conn = get_connection()
        c = conn.cursor()
        
        try:
            for addr in addresses:
                # Fetch signatures for this address
                c.execute("SELECT r_int, s_int, txid FROM signatures WHERE address = ?", (addr,))
                sigs = []
                for row in c.fetchall():
                    try:
                        sigs.append({
                            'r': int(row[0]) if row[0] else 0,
                            's': int(row[1]) if row[1] else 0,
                            'txid': row[2]
                        })
                    except ValueError:
                        continue
                
                if sigs:
                    # Run the TCG collision search with the mutated parameters
                    found = tcg_collision_search(sigs, addr, params=current_params)
                    if not found and not is_evolutionary_run:
                        update_fail_att(addr, 6)
                
                # Mark as done / Release
                if not is_evolutionary_run:
                    mark_stage_done(addr, 'tcg', self.worker_id)
                else:
                    release_address(addr, self.worker_id)
                
        except Exception as e:
            self.heartbeat("TCG Scan: ERROR")
            self.log(f"TCG scan error: {e}")
            for addr in addresses:
                release_address(addr, self.worker_id)
        finally:
            conn.close()

        # Brief delay to allow context switching
        time.sleep(1.5)

if __name__ == "__main__":
    worker_id = f"tcg_{os.getpid()}"
    TCGWorker(worker_id, "TCG Evolutionary Search").run()
