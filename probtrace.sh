#!/bin/bash

today=$(date +%Y-%m-%d_%H-%M-%S)
logfile="logfile_prob_$today.txt"
echo "Log file: $logfile"

#Finalize parameters
#cargo run --example tracing -- --nocapture 4 8 30 >> "$logfile"

for i in {1..20}
do
    echo "Run #$i" >> "$logfile"
    cargo run --example tracing -- --nocapture 4 16 5 >> "$logfile"
    echo "" >> "$logfile"
done
