#!/bin/bash
# Start Bitcoin Miner in background
nohup python3 bitcoin_miner.py > miner.log 2>&1 &
echo "[*] Bitcoin Miner started in background (PID: $!)"
echo "[*] You can monitor it by running: python3 miner_dash.py"
echo "[*] To stop it: kill $!"
