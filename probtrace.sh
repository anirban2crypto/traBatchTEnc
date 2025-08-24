#!/bin/bash

today=$(date +%Y-%m-%d_%H-%M-%S)
logfile="logfile_trace_$today.txt"
echo "Log file: $logfile"

for i in {1..20}
do
    echo "Run #$i" >> "$logfile"
    cargo run --example tracing -- --nocapture 4 8 40 >> "$logfile"
    echo "" >> "$logfile"
done
