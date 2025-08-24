#!/bin/bash

today=`date +%Y-%m-%d_%H-%M-%S`
logfile=logfile_trace_$today.txt
echo "Log file: $logfile"


echo "For Table 4, number of parties n = 16" >> $logfile

cargo run --example tracing  -- --nocapture 16 15 >> $logfile
cargo run --example tracing  -- --nocapture 16 20 >> $logfile
cargo run --example tracing  -- --nocapture 16 25 >> $logfile



