#!/bin/bash
echo "Initializing CryScout Hub (Service Mode)..."

HUB_BIN="./target/release/cryshub_rs"

if [ ! -f "$HUB_BIN" ]; then
    echo "Error: Hub binary not found at $HUB_BIN. Build it first with 'cargo build --release'"
    exit 1
fi

# Kill any existing hub or workers
echo "Cleaning up existing processes..."
pkill -f cryshub_rs
pkill -f cryscout_worker_rs
pkill -f wallet_scout_rs
pkill -f address_analyzer_rs
pkill -f neural_scout_rs
pkill -f crypdash_rs
pkill -f lattice_attack_rs

# Start Hub in background
echo "Starting CryScout Hub..."
nohup $HUB_BIN > hub_live.log 2>&1 &
HUB_PID=$!

echo "Hub started with PID $HUB_PID. Workers will stagger start automatically."
sleep 5
ps aux | grep _rs | grep -v grep
