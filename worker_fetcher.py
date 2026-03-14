#!/usr/bin/env python3
import os
import asyncio
import random
import time
from base_worker import BaseWorker
from db_manager import claim_address, release_address, get_connection, mark_stage_done, save_signatures, mark_stages_done
from tx_preimage_reconstructor import async_extract_sigs_from_txids, extract_sigs_with_real_z

class AsyncFetcherWorker(BaseWorker):
    def __init__(self, worker_id, task_name):
        super().__init__(worker_id, task_name)
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    async def process_loop_async(self):
        addresses = await self.loop.run_in_executor(None, claim_address, self.worker_id, 'fetching', 3)
        
        if not addresses:
            # Check if we need to replenish the target pool
            conn = await self.loop.run_in_executor(None, get_connection)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM addresses WHERE sigs_fetched = 0 AND analyzed = 0")
            remaining = c.fetchone()[0]
            conn.close()
            
            if remaining < 10:
                self.log("POOL EXHAUSTED. Replenishing 1000+ high-value Satoshi-Era & Dormant targets...")
                self.heartbeat("Replenishing targets...")
                from replenish_targets import replenish_high_value_targets
                # Run the surgical replenishment in an executor
                await self.loop.run_in_executor(None, replenish_high_value_targets, 1000)
                await asyncio.sleep(5)
                return

            self.heartbeat("Idle (Waiting for targets)")
            await asyncio.sleep(20)
            return

        for addr in addresses:
            self.heartbeat(f"Fetching: {addr[:15]}...")
            self.log(f"Fetching signatures for {addr}...")
            
            try:
                # 1. Get txids (sync for now as it's one call)
                from api_client import api
                txids = api.get_address_txids(addr, max_txs=10000)
                
                if txids:
                    # 2. Extract sigs asynchronously (this is the big gain)
                    sigs = await async_extract_sigs_from_txids(addr, txids, max_sigs=10000)
                    if sigs:
                        await self.loop.run_in_executor(None, save_signatures, addr, sigs)
                        self.log(f"  Got {len(sigs)} sigs for {addr}")
                        await self.loop.run_in_executor(None, mark_stage_done, addr, 'fetching', self.worker_id)
                    else:
                        self.log(f"  Transactions exist but no signatures extracted for {addr}")
                        # Mark all stages as done since no signatures exist
                        await self.loop.run_in_executor(None, mark_stages_done, addr, ['fetching', 'analyzing', 'scanning', 'neural', 'tcg'], self.worker_id)
                else:
                    self.log(f"  No spending transactions for {addr}")
                    # Fast-track to analyzed since there is nothing for signature workers to do
                    await self.loop.run_in_executor(None, mark_stages_done, addr, ['fetching', 'analyzing', 'scanning', 'neural', 'tcg'], self.worker_id)
                    
            except Exception as e:
                self.log(f"Error fetching {addr}: {e}")
                await self.loop.run_in_executor(None, release_address, addr, self.worker_id)
            
            await asyncio.sleep(random.uniform(1, 2))

    def process_loop(self):
        self.loop.run_until_complete(self.process_loop_async())

if __name__ == "__main__":
    worker_id = f"fetcher_{os.getpid()}"
    AsyncFetcherWorker(worker_id, "Sig Fetching (Async)").run()
