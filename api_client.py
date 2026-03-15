#!/usr/bin/env python3
"""
Phase 2.3 — Enhanced Multi-source Bitcoin API client.
Supports: mempool.space, blockchair.com, blockchain.info, Esplora, Bitcoin RPC
Features: exponential backoff, user-agent rotation, automatic failover.
"""
import requests
import time
import json
import random

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
    'CryScout/2.0 (Research; +https://github.com/cryscout)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0.0.0',
]

class BitcoinAPI:
    def __init__(self, rpc_url=None, rpc_user=None, rpc_pass=None):
        self.sources = [
            {'name': 'mempool', 'base': 'https://mempool.space/api', 'rate': 0.3, 'last': 0, 'fails': 0},
            {'name': 'blockchair', 'base': 'https://api.blockchair.com/bitcoin', 'rate': 0.6, 'last': 0, 'fails': 0},
            {'name': 'blockchain', 'base': 'https://blockchain.info', 'rate': 0.4, 'last': 0, 'fails': 0},
            {'name': 'esplora', 'base': 'https://blockstream.info/api', 'rate': 0.3, 'last': 0, 'fails': 0},
        ]
        self.session = requests.Session()
        self._rotate_ua()
        
        # Bitcoin RPC config (optional — for local full node)
        self.rpc_url = rpc_url or 'http://127.0.0.1:8332'
        self.rpc_user = rpc_user
        self.rpc_pass = rpc_pass
        self.rpc_available = False
        if rpc_user and rpc_pass:
            self._check_rpc()
    
    def _rotate_ua(self):
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
    
    def _check_rpc(self):
        """Check if Bitcoin RPC is available."""
        try:
            resp = self.session.post(self.rpc_url, json={
                'jsonrpc': '1.0', 'id': 'test', 'method': 'getblockchaininfo', 'params': []
            }, auth=(self.rpc_user, self.rpc_pass), timeout=5)
            if resp.status_code == 200:
                self.rpc_available = True
                print("[API] Bitcoin RPC connected!")
        except:
            self.rpc_available = False
    
    def _rate_limit(self, source):
        elapsed = time.time() - source['last']
        # Exponential backoff on repeated failures
        backoff = source['rate'] * (2 ** min(source['fails'], 5))
        if elapsed < backoff:
            time.sleep(backoff - elapsed)
        source['last'] = time.time()
    
    def _get(self, source, path, params=None, max_retries=3):
        for attempt in range(max_retries):
            self._rate_limit(source)
            self._rotate_ua()
            try:
                resp = self.session.get(f"{source['base']}{path}", params=params, timeout=20)
                if resp.status_code == 429:
                    wait = min(10 * (2 ** attempt), 60)
                    print(f"  [{source['name']}] Rate limited, waiting {wait}s (attempt {attempt+1})")
                    time.sleep(wait)
                    source['fails'] = min(source['fails'] + 1, 10)
                    continue
                if resp.status_code == 200:
                    source['fails'] = max(0, source['fails'] - 1)  # Decay failures
                return resp
            except requests.exceptions.ConnectionError:
                source['fails'] += 1
                time.sleep(2 * (attempt + 1))
            except requests.exceptions.Timeout:
                source['fails'] += 1
                time.sleep(1)
            except Exception as e:
                print(f"  [{source['name']}] Error: {e}")
                return None
        return None

    def get_address_txids(self, address, max_txs=500):
        """Get all transaction IDs for an address (spending TXes only)."""
        txids = []
        
        # Try mempool.space first (paginated)
        src = self.sources[0]
        last_txid = None
        for page in range(max_txs // 25 + 1):
            path = f"/address/{address}/txs/chain"
            if last_txid:
                path += f"/{last_txid}"
            resp = self._get(src, path)
            if not resp or resp.status_code != 200:
                break
            txs = resp.json()
            if not txs:
                break
            for tx in txs:
                if not tx or not isinstance(tx, dict): continue
                for vin in tx.get('vin', []):
                    if not vin or not isinstance(vin, dict): continue
                    prevout = vin.get('prevout') or {}
                    if prevout.get('scriptpubkey_address') == address:
                        txids.append(tx['txid'])
                        break
                last_txid = tx['txid']
            if len(txids) >= max_txs:
                break
            time.sleep(0.15)
        
        if txids:
            return list(dict.fromkeys(txids))
        
        # Fallback: Esplora (blockstream)
        src = self.sources[3]
        last_txid = None
        for page in range(max_txs // 25 + 1):
            path = f"/address/{address}/txs/chain"
            if last_txid:
                path += f"/{last_txid}"
            resp = self._get(src, path)
            if not resp or resp.status_code != 200:
                break
            txs = resp.json()
            if not txs:
                break
            for tx in txs:
                if not tx or not isinstance(tx, dict): continue
                for vin in tx.get('vin', []):
                    if not vin or not isinstance(vin, dict): continue
                    prevout = vin.get('prevout') or {}
                    if prevout.get('scriptpubkey_address') == address:
                        txids.append(tx['txid'])
                        break
                last_txid = tx['txid']
            if len(txids) >= max_txs:
                break
            time.sleep(0.15)
        
        if txids:
            return list(dict.fromkeys(txids))
        
        # Fallback: blockchair
        src = self.sources[1]
        resp = self._get(src, f"/dashboards/address/{address}", params={'limit': '500', 'offset': '0'})
        if resp and resp.status_code == 200:
            data = resp.json()
            addr_data = data.get('data', {}).get(address, {})
            all_txids = addr_data.get('transactions', [])
            return all_txids[:max_txs]
        
        # Fallback: blockchain.info (supports offset up to 1000+)
        src = self.sources[2]
        for offset in range(0, min(max_txs, 2000), 100):
            resp = self._get(src, f"/rawaddr/{address}", params={'limit': 100, 'offset': offset})
            if resp and resp.status_code == 200:
                data = resp.json()
                txs = data.get('txs', [])
                if not txs: break
                for tx in txs:
                    for inp in tx.get('inputs', []):
                        prev_out = inp.get('prev_out', {})
                        if prev_out.get('addr') == address:
                            txids.append(tx['hash'])
                            break
                if len(txids) >= max_txs: break
            else:
                break
        return list(dict.fromkeys(txids))
        
        # Last resort: Bitcoin RPC
        if self.rpc_available:
            return self._rpc_get_address_txids(address)
        
        return []
    
    def _rpc_get_address_txids(self, address):
        """Get TXIDs via Bitcoin Core RPC (requires txindex=1)."""
        try:
            # scantxoutset to find UTXOs
            resp = self.session.post(self.rpc_url, json={
                'jsonrpc': '1.0', 'id': 'scan',
                'method': 'scantxoutset', 
                'params': ['start', [f'addr({address})']]
            }, auth=(self.rpc_user, self.rpc_pass), timeout=60)
            if resp.status_code == 200:
                result = resp.json().get('result', {})
                txids = []
                for utxo in result.get('unspents', []):
                    txids.append(utxo.get('txid'))
                return txids
        except:
            pass
        return []
    
    def get_tx_data(self, txid):
        """Get full transaction data with failover."""
        # Try mempool.space
        src = self.sources[0]
        resp = self._get(src, f"/tx/{txid}")
        if resp and resp.status_code == 200:
            return resp.json()
        
        # Try Esplora
        src = self.sources[3]
        resp = self._get(src, f"/tx/{txid}")
        if resp and resp.status_code == 200:
            return resp.json()
        
        # Try blockchair
        src = self.sources[1]
        resp = self._get(src, f"/raw/transaction/{txid}")
        if resp and resp.status_code == 200:
            data = resp.json()
            return data.get('data', {}).get(txid, {}).get('decoded_raw_transaction')
        
        # Try RPC
        if self.rpc_available:
            try:
                resp = self.session.post(self.rpc_url, json={
                    'jsonrpc': '1.0', 'id': 'gettx',
                    'method': 'getrawtransaction',
                    'params': [txid, True]
                }, auth=(self.rpc_user, self.rpc_pass), timeout=15)
                if resp.status_code == 200:
                    return resp.json().get('result')
            except:
                pass
        
        return None
    
    def get_address_info(self, address):
        """Get address balance and basic info with failover."""
        # Try mempool.space
        src = self.sources[0]
        resp = self._get(src, f"/address/{address}")
        if resp and resp.status_code == 200:
            data = resp.json()
            stats = data.get('chain_stats', {})
            return {
                'funded_txo_count': stats.get('funded_txo_count', 0),
                'spent_txo_count': stats.get('spent_txo_count', 0),
                'balance': stats.get('funded_txo_sum', 0) - stats.get('spent_txo_sum', 0),
                'tx_count': stats.get('tx_count', 0),
            }
        
        # Try Esplora
        src = self.sources[3]
        resp = self._get(src, f"/address/{address}")
        if resp and resp.status_code == 200:
            data = resp.json()
            stats = data.get('chain_stats', {})
            return {
                'funded_txo_count': stats.get('funded_txo_count', 0),
                'spent_txo_count': stats.get('spent_txo_count', 0),
                'balance': stats.get('funded_txo_sum', 0) - stats.get('spent_txo_sum', 0),
                'tx_count': stats.get('tx_count', 0),
            }
        
        return None

import aiohttp
import asyncio

class AsyncBitcoinAPI:
    def __init__(self):
        self.sources = [
            {'name': 'mempool', 'base': 'https://mempool.space/api', 'rate': 0.3},
            {'name': 'esplora', 'base': 'https://blockstream.info/api', 'rate': 0.3},
        ]
        self.headers = {'User-Agent': random.choice(USER_AGENTS)}

    async def get_address_txids(self, address, max_txs=10000):
        async with aiohttp.ClientSession(headers=self.headers) as session:
            # Try mempool
            try:
                async with session.get(f"{self.sources[0]['base']}/address/{address}/txs/chain", timeout=15) as resp:
                    if resp.status == 200:
                        txs = await resp.json()
                        txids = []
                        for tx in txs:
                            if not tx or not isinstance(tx, dict): continue
                            for vin in tx.get('vin', []):
                                if vin.get('prevout', {}).get('scriptpubkey_address') == address:
                                    txids.append(tx['txid'])
                                    break
                        return txids[:max_txs]
            except: pass
            return []

    async def get_tx_data(self, txid):
        async with aiohttp.ClientSession(headers=self.headers) as session:
            for src in self.sources:
                try:
                    async with session.get(f"{src['base']}/tx/{txid}", timeout=10) as resp:
                        if resp.status == 200:
                            return await resp.json()
                except: continue
        return None

async_api = AsyncBitcoinAPI()

# Singleton
api = BitcoinAPI()
