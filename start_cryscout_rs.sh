#!/bin/bash
echo "Starting CryScout (Rust Edition)..."

# Start the Hub in the background
./target/release/cryshub_rs &
HUB_PID=$!

sleep 1

# Start the Dashboard
./target/release/crypdash_rs

# On dashboard exit, kill the hub
kill -TERM $HUB_PID
echo "CryScout shut down."
