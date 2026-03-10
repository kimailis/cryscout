#!/usr/bin/env python3
import socket
import json
import hashlib
import time
import binascii
import multiprocessing
import sys
import os
import psutil

# Configuration
POOL_HOST = "solo.ckpool.org"
POOL_PORT = 3333
POOL_USER = "bc1qq8y2ut4w50nnq6dgdf3vrhj026y5ya2aysw08q" # Example BTC address
POOL_PASS = "x"

# CPU/RAM Limit Settings
CPU_PERCENT_TARGET = 50
RAM_LIMIT_PERCENT = 50
STATUS_FILE = "miner_status.json"

def sha256d(data):
    """Double SHA-256 hashing."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def miner_worker(id, job_queue, result_queue, stop_event):
    """Worker process that performs the actual hashing."""
    p = psutil.Process(os.getpid())
    try:
        p.nice(10)
    except:
        pass
        
    hashes_done = 0
    start_time = time.time()
    
    while not stop_event.is_set():
        try:
            job = job_queue.get(timeout=1)
            
            job_id = job['job_id']
            prevhash = job['prevhash']
            coinb1 = job['coinb1']
            coinb2 = job['coinb2']
            merkle_branch = job['merkle_branch']
            version = job['version']
            nbits = job['nbits']
            ntime = job['ntime']
            extranonce2_size = job['extranonce2_size']
            extranonce1 = job['extranonce1']
            target = job['target']
            
            en2_val = 0
            
            while not stop_event.is_set():
                if not job_queue.empty():
                    break
                
                en2 = hex(en2_val)[2:].zfill(extranonce2_size * 2)
                coinbase = coinb1 + extranonce1 + en2 + coinb2
                coinbase_hash = sha256d(binascii.unhexlify(coinbase))
                
                merkle_root = coinbase_hash
                for branch in merkle_branch:
                    merkle_root = sha256d(merkle_root + binascii.unhexlify(branch))
                
                header_prefix = binascii.unhexlify(version + prevhash) + merkle_root + binascii.unhexlify(ntime + nbits)
                
                for nonce in range(0, 0xffffffff, 5000):
                    if stop_event.is_set() or not job_queue.empty():
                        break
                        
                    for i in range(5000):
                        current_nonce = hex(nonce + i)[2:].zfill(8)
                        n_bytes = binascii.unhexlify(current_nonce)[::-1]
                        
                        header = header_prefix + n_bytes
                        hash_result = sha256d(header)[::-1]
                        
                        hashes_done += 1
                        if hash_result.hex() < target:
                            result_queue.put({
                                'type': 'share',
                                'job_id': job_id,
                                'extranonce2': en2,
                                'ntime': ntime,
                                'nonce': current_nonce
                            })
                    
                    # Periodic speed reporting
                    elapsed = time.time() - start_time
                    if elapsed > 5:
                        hashrate = hashes_done / elapsed
                        result_queue.put({
                            'type': 'stat',
                            'worker_id': id,
                            'hashrate': hashrate
                        })
                        hashes_done = 0
                        start_time = time.time()

                    # Simple CPU throttling if needed
                    # (In Python, the GIL and overhead already limit us, 
                    # but we can sleep to be even more conservative)
                    time.sleep(0.001) 
                            
                en2_val += 1
                
        except Exception:
            time.sleep(1)

class BitcoinMinerService:
    def __init__(self):
        self.sock = None
        self.rpc_id = 1
        self.extranonce1 = None
        self.extranonce2_size = None
        self.job_queue = multiprocessing.Queue()
        self.result_queue = multiprocessing.Queue()
        self.stop_event = multiprocessing.Event()
        self.workers = []
        self.worker_hashrates = {}
        self.shares_found = 0
        self.start_time = time.time()
        
        cpu_count = multiprocessing.cpu_count()
        self.num_workers = max(1, int(cpu_count * (CPU_PERCENT_TARGET / 100.0)))
        print(f"[*] Starting {self.num_workers} workers (Target: {CPU_PERCENT_TARGET}% CPU)")

    def update_status(self, current_task="Mining"):
        total_hashrate = sum(self.worker_hashrates.values())
        cpu_usage = psutil.cpu_percent()
        ram_usage = psutil.virtual_memory().percent
        
        status = {
            "running": not self.stop_event.is_set(),
            "current_task": current_task,
            "hashrate": round(total_hashrate, 2),
            "shares_found": self.shares_found,
            "cpu_usage": cpu_usage,
            "ram_usage": ram_usage,
            "uptime": int(time.time() - self.start_time),
            "last_heartbeat": time.time(),
            "workers": self.num_workers,
            "pool": POOL_HOST
        }
        with open(STATUS_FILE, 'w') as f:
            json.dump(status, f)

    def send_rpc(self, method, params):
        request = json.dumps({"id": self.rpc_id, "method": method, "params": params}) + "\n"
        self.sock.sendall(request.encode())
        self.rpc_id += 1

    def connect(self):
        print(f"[*] Connecting to {POOL_HOST}:{POOL_PORT}...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((POOL_HOST, POOL_PORT))
        
        # Subscribe
        self.send_rpc("mining.subscribe", [])
        
        # Read until we get a result for our subscribe (id: 1)
        sock_file = self.sock.makefile()
        while True:
            line = sock_file.readline()
            if not line: break
            data = json.loads(line)
            if data.get('id') == 1:
                self.extranonce1 = data['result'][1]
                self.extranonce2_size = data['result'][2]
                break
        
        # Authorize
        self.send_rpc("mining.authorize", [POOL_USER, POOL_PASS])
        # We don't strictly need to wait for auth result to start, 
        # but we should clear the buffer

    def start_workers(self):
        for i in range(self.num_workers):
            p = multiprocessing.Process(target=miner_worker, args=(i, self.job_queue, self.result_queue, self.stop_event))
            p.start()
            self.workers.append(p)

    def run(self):
        self.connect()
        self.start_workers()
        
        sock_file = self.sock.makefile()
        last_status_update = 0
        
        try:
            while True:
                # Check for results (shares or stats)
                while not self.result_queue.empty():
                    msg = self.result_queue.get()
                    if msg['type'] == 'share':
                        print(f"[*] Submitting share for job {msg['job_id']}...")
                        self.send_rpc("mining.submit", [
                            POOL_USER, 
                            msg['job_id'], 
                            msg['extranonce2'], 
                            msg['ntime'], 
                            msg['nonce']
                        ])
                        self.shares_found += 1
                    elif msg['type'] == 'stat':
                        self.worker_hashrates[msg['worker_id']] = msg['hashrate']

                if time.time() - last_status_update > 2:
                    self.update_status()
                    last_status_update = time.time()

                # Read from socket with timeout
                try:
                    line = sock_file.readline()
                    if not line:
                        break
                    
                    data = json.loads(line)
                    if data.get('method') == 'mining.notify':
                        params = data['params']
                        job_id = params[0]
                        prevhash = params[1]
                        coinb1 = params[2]
                        coinb2 = params[3]
                        merkle_branch = params[4]
                        version = params[5]
                        nbits = params[6]
                        ntime = params[7]
                        clean_jobs = params[8]
                        
                        # Calculate target from nbits
                        nbits_int = int(nbits, 16)
                        exponent = nbits_int >> 24
                        mantissa = nbits_int & 0xffffff
                        target_int = mantissa * 2**(8*(exponent - 3))
                        target = hex(target_int)[2:].zfill(64)
                        
                        job = {
                            'job_id': job_id,
                            'prevhash': prevhash,
                            'coinb1': coinb1,
                            'coinb2': coinb2,
                            'merkle_branch': merkle_branch,
                            'version': version,
                            'nbits': nbits,
                            'ntime': ntime,
                            'extranonce1': self.extranonce1,
                            'extranonce2_size': self.extranonce2_size,
                            'target': target
                        }
                        
                        if clean_jobs:
                            while not self.job_queue.empty():
                                try: self.job_queue.get_nowait()
                                except: pass
                        
                        self.job_queue.put(job)
                        # print(f"[*] New Job Received: {job_id}")
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[!] Socket Error: {e}")
                    break
        finally:
            self.stop_event.set()
            self.update_status("Stopped")
            for p in self.workers:
                p.terminate()
            self.sock.close()

if __name__ == "__main__":
    miner = BitcoinMinerService()
    try:
        miner.run()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        miner.stop_event.set()
        sys.exit(0)
