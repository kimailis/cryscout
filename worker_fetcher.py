#!/usr/bin/env python3
import os
import asyncio
import random
import time
from base_worker import BaseWorker
from db_manager import claim_address, release_address, get_connection, mark_stage_done, save_signatures
from tx_preimage_reconstructor import async_extract_sigs_from_txids, extract_sigs_with_real_z

class AsyncFetcherWorker(BaseWorker):
    async def process_loop_async(self):
        # We wrap the sync claim_address in an executor
        loop = asyncio.get_event_loop()
        addresses = await loop.run_in_executor(None, claim_address, self.worker_id, 'fetching', 3)
        
        if not addresses:
            self.heartbeat("Idle (Waiting for targets)")
            await asyncio.sleep(10)
            return

        for addr in addresses:
            self.heartbeat(f"Fetching: {addr[:15]}...")
            self.log(f"Fetching signatures for {addr}...")
            
            try:
                # 1. Get txids (sync for now as it's one call)
                from api_client import api
                txids = api.get_address_txids(addr, max_txs=100)
                
                if txids:
                    # 2. Extract sigs asynchronously (this is the big gain)
                    sigs = await async_extract_sigs_from_txids(addr, txids, max_sigs=256)
                    if sigs:
                        await loop.run_in_executor(None, save_signatures, addr, sigs)
                        self.log(f"  Got {len(sigs)} sigs for {addr}")
                    
                    await loop.run_in_executor(None, mark_stage_done, addr, 'fetching', self.worker_id)
                else:
                    self.log(f"  No spending transactions for {addr}")
                    await loop.run_in_executor(None, mark_stage_done, addr, 'fetching', self.worker_id)
                    
            except Exception as e:
                self.log(f"Error fetching {addr}: {e}")
                await loop.run_in_executor(None, release_address, addr, self.worker_id)
            
            await asyncio.sleep(random.uniform(1, 2))

    def process_loop(self):
        # BaseWorker calls this sync, so we run our async loop
        asyncio.run(self.process_loop_async())

if __name__ == "__main__":
    worker_id = f"fetcher_{os.getpid()}"
    AsyncFetcherWorker(worker_id, "Sig Fetching (Async)").run()
