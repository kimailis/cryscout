#!/usr/bin/env python3
import os
import time
from base_worker import BaseWorker
from cluster_manager import run_clustering

class ClusterWorker(BaseWorker):
    def process_loop(self):
        self.heartbeat("Clustering signatures...")
        try:
            run_clustering()
            self.heartbeat("Idle (Clustering Done)")
        except Exception as e:
            self.log(f"Clustering error: {e}")
            
        # Clustering is expensive, so we don't need to run it every second.
        # Run every 5 minutes or so.
        for _ in range(300):
            if not self.running: break
            time.sleep(1)

if __name__ == "__main__":
    worker_id = f"cluster_{os.getpid()}"
    ClusterWorker(worker_id, "Library Fingerprinting & Clustering").run()
