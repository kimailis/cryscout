#!/bin/bash
echo "Initializing CryScout Rust Environment (Service Mode)..."

# Ensure binaries are built
cargo build --release --quiet

HUB_BIN="./target/release/cryshub_rs"

if [ ! -f "$HUB_BIN" ]; then
    echo "Error: Hub binary not found at $HUB_BIN"
    exit 1
fi

# Kill any existing hub or workers
pkill -f cryshub_rs
pkill -f cryscout_worker_rs
pkill -f wallet_scout_rs

# Start Hub in background
echo "Starting CryScout Hub..."
$HUB_BIN > hub_live.log 2>&1 &
HUB_PID=$!

# Give hub a second to start then send RESTART signal to boot workers
sleep 2
echo "RESTART" > service_signal.txt

echo "Hub started with PID $HUB_PID. Monitoring workers..."
sleep 5
ps aux | grep _rs | grep -v grep
