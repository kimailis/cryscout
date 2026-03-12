#!/usr/bin/env python3
"""
Phase 4.1 — Satoshi Era & Dormancy Replenishment Service

Orchestrates the surgical fetching of 1000+ high-value targets (>100 BTC)
that are:
1. Dormant for >10 years (BitInfoCharts)
2. Satoshi Era P2PK (Direct Blockchain extraction)
3. Early era Legacy (Block analysis)
"""
import time
import random
import requests
from db_manager import get_connection, upsert_address
from fetch_dormant_targets import scrape_bitinfo_pages
from fetch_older_era import fetch_satoshi_era_p2pk

def replenish_high_value_targets(target_count=1000):
    print("=" * 60)
    print(f"REPLENISHING TARGET POOL (Target: {target_count} High-Value Addresses)")
    print("=" * 60)
    
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM addresses")
    before = c.fetchone()[0]
    conn.close()

    # 1. Fetch Dormant Rich List (BitInfoCharts)
    # Scrape ~30 pages to get up to 3000 high-balance dormant targets
    print("\n[Phase 1] Scraping Dormant Rich List (>100 BTC, >10y)...")
    scrape_bitinfo_pages(pages=30)
    
    # 2. Fetch Satoshi Era P2PK (Direct Blockchain Analysis)
    # We scan a random set of early blocks (0 - 30,000)
    print("\n[Phase 2] Analyzing Satoshi Era Blocks for P2PK (0-30,000)...")
    start = random.randint(100, 25000)
    fetch_satoshi_era_p2pk(start_block=start, end_block=start + 1000, step=50)
    
    # 3. Fetch Early Legacy (Direct Blockchain Analysis)
    # We scan another random set of blocks from 2011-2013 (100k - 250k)
    print("\n[Phase 3] Analyzing Early Legacy Blocks (100k-250k)...")
    start_mid = random.randint(100000, 240000)
    fetch_satoshi_era_p2pk(start_block=start_mid, end_block=start_mid + 1000, step=100)

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM addresses")
    after = c.fetchone()[0]
    conn.close()
    
    added = after - before
    print("=" * 60)
    print(f"REPLENISHMENT COMPLETE: {added} new targets added.")
    print(f"Total Database Pool: {after} addresses.")
    print("=" * 60)
    return added

if __name__ == "__main__":
    replenish_high_value_targets(1000)
