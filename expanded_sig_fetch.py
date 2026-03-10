#!/usr/bin/env python3
"""
Phase 2.3 — Expanded Signature Collection

Targets addresses with high TX counts but low collected sig counts.
Uses the enhanced API client with Esplora failover and exponential backoff.
Prioritizes the specific high-value addresses identified in the roadmap:
  - 12ib7dAp... — 250 TXs, only 4 sigs collected (31K BTC)
  - 15Z5YJaa... — 138 TXs, only 60 sigs (8K BTC)
  - 17rm2dvb... — 118 TXs, only 1 sig (20K BTC)
  - 1GR9qNz7... — 108 TXs, only 1 sig (16K BTC)
"""
import time
from db_manager import get_connection, save_signatures, mark_analyzed
from tx_preimage_reconstructor import extract_sigs_with_real_z, extract_sigs_from_txids
from api_client import api


def get_underfetched_addresses(max_addresses=10):
    """
    Find addresses with high TX count but low collected sig count.
    These are the best targets for expanded signature collection.
    """
    conn = get_connection()
    c = conn.cursor()
    
    # Find addresses where we have significantly fewer sigs than expected
    c.execute("""
        SELECT a.address, a.transactions, 
               COALESCE(s.sig_count, 0) as collected_sigs,
               COALESCE(a.current_balance, a.balance, 0) as bal
        FROM addresses a
        LEFT JOIN (SELECT address, COUNT(*) as sig_count FROM signatures GROUP BY address) s
            ON a.address = s.address
        WHERE a.transactions > 5
          AND COALESCE(s.sig_count, 0) < a.transactions
          AND a.status IN ('Spent/Active', 'Target')
        ORDER BY (a.transactions - COALESCE(s.sig_count, 0)) DESC, bal DESC
        LIMIT ?
    """, (max_addresses,))
    
    rows = c.fetchall()
    conn.close()
    return rows


def fetch_sigs_for_address(address, existing_count, max_sigs=500):
    """Fetch additional signatures using multi-source API with retries."""
    needed = max_sigs - existing_count
    if needed <= 0:
        return existing_count
    
    total_new = 0
    
    # Method 1: Direct extraction from mempool.space / Esplora
    try:
        sigs = extract_sigs_with_real_z(address, max_pages=100, max_sigs=needed)
        if sigs:
            save_signatures(address, sigs)
            total_new += len(sigs)
            print(f"    Primary source: +{len(sigs)} sigs")
    except Exception as e:
        print(f"    Primary source failed: {e}")
    
    if total_new >= needed:
        return existing_count + total_new
    
    # Method 2: Fetch TXIDs from multiple sources, then reconstruct
    remaining = needed - total_new
    try:
        txids = api.get_address_txids(address, max_txs=500)
        if txids:
            print(f"    Found {len(txids)} TXIDs from API sources")
            sigs = extract_sigs_from_txids(address, txids, max_sigs=remaining)
            if sigs:
                save_signatures(address, sigs)
                total_new += len(sigs)
                print(f"    API fallback: +{len(sigs)} sigs")
    except Exception as e:
        print(f"    API fallback failed: {e}")
    
    return existing_count + total_new


def fetch_expanded_sigs(max_addresses=10):
    """Main entry point: fetch expanded signatures for underfetched addresses."""
    print("=" * 60)
    print("EXPANDED SIGNATURE COLLECTION")
    print("=" * 60)
    
    targets = get_underfetched_addresses(max_addresses)
    
    if not targets:
        print("  No underfetched addresses found")
        return
    
    print(f"  Found {len(targets)} addresses needing more signatures:")
    for addr, tx_count, sig_count, bal in targets:
        gap = tx_count - sig_count
        print(f"    {addr[:30]}... TXs: {tx_count}, Sigs: {sig_count}, Gap: {gap}, Bal: {bal} BTC")
    
    total_new = 0
    for addr, tx_count, sig_count, bal in targets:
        print(f"\n  Fetching for {addr[:30]}... (have {sig_count}/{tx_count})")
        new_count = fetch_sigs_for_address(addr, sig_count, max_sigs=tx_count)
        added = new_count - sig_count
        total_new += added
        print(f"    Result: {sig_count} -> {new_count} sigs (+{added})")
        time.sleep(0.5)  # Be nice to APIs
    
    print(f"\n  Expanded sig collection complete: +{total_new} new sigs total")
    return total_new


if __name__ == "__main__":
    import sys
    max_addr = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    fetch_expanded_sigs(max_addresses=max_addr)
