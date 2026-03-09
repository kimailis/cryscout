#!/usr/bin/env python3
"""
Multi-source API client for Bitcoin data.
Supports: mempool.space, blockchair.com, blockchain.info
Handles rate limiting and failover between sources.
"""
import requests
import time
import json

class BitcoinAPI:
    def __init__(self):
        self.sources = [
            {'name': 'mempool', 'base': 'https://mempool.space/api', 'rate': 0.2, 'last': 0},
            {'name': 'blockchair', 'base': 'https://api.blockchair.com/bitcoin', 'rate': 0.5, 'last': 0},
            {'name': 'blockchain', 'base': 'https://blockchain.info', 'rate': 0.3, 'last': 0},
        ]
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'CryScout/1.0'})
    
    def _rate_limit(self, source):
        elapsed = time.time() - source['last']
        if elapsed < source['rate']:
            time.sleep(source['rate'] - elapsed)
        source['last'] = time.time()
    
    def _get(self, source, path, params=None):
        self._rate_limit(source)
        try:
            resp = self.session.get(f"{source['base']}{path}", params=params, timeout=20)
            if resp.status_code == 429:
                print(f"  [{source['name']}] Rate limited, waiting 10s...")
                time.sleep(10)
                return self._get(source, path, params)
            return resp
        except Exception as e:
            print(f"  [{source['name']}] Error: {e}")
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
                for vin in tx.get('vin', []):
                    if vin.get('prevout', {}).get('scriptpubkey_address') == address:
                        txids.append(tx['txid'])
                        break
                last_txid = tx['txid']
            if len(txids) >= max_txs:
                break
            time.sleep(0.1)
        
        if txids:
            return list(dict.fromkeys(txids))  # Deduplicate preserving order
        
        # Fallback to blockchair
        print(f"  Trying blockchair for {address}...")
        src = self.sources[1]
        resp = self._get(src, f"/dashboards/address/{address}", params={'limit': '500', 'offset': '0'})
        if resp and resp.status_code == 200:
            data = resp.json()
            addr_data = data.get('data', {}).get(address, {})
            all_txids = addr_data.get('transactions', [])
            # Blockchair returns all TXIDs, we need to filter spending ones later
            return all_txids[:max_txs]
        
        # Fallback to blockchain.info
        print(f"  Trying blockchain.info for {address}...")
        src = self.sources[2]
        resp = self._get(src, f"/rawaddr/{address}", params={'limit': 500})
        if resp and resp.status_code == 200:
            data = resp.json()
            for tx in data.get('txs', []):
                for inp in tx.get('inputs', []):
                    prev_out = inp.get('prev_out', {})
                    if prev_out.get('addr') == address:
                        txids.append(tx['hash'])
                        break
            return list(dict.fromkeys(txids))
        
        return []
    
    def get_tx_data(self, txid):
        """Get full transaction data."""
        # Try mempool.space first
        src = self.sources[0]
        resp = self._get(src, f"/tx/{txid}")
        if resp and resp.status_code == 200:
            return resp.json()
        
        # Fallback to blockchair
        src = self.sources[1]
        resp = self._get(src, f"/raw/transaction/{txid}")
        if resp and resp.status_code == 200:
            data = resp.json()
            return data.get('data', {}).get(txid, {}).get('decoded_raw_transaction')
        
        return None
    
    def get_address_info(self, address):
        """Get address balance and basic info."""
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
        return None

# Singleton
api = BitcoinAPI()
