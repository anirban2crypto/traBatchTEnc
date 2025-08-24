#!/bin/bash

today=`date +%Y-%m-%d_%H-%M-%S`
logfile=logfile_trace_$today.txt
echo "Log file: $logfile"


echo "For Table 4, number of parties n = 16" >> $logfile

cargo run --example tracing  -- --nocapture 4 15 >> $logfile
cargo run --example tracing  -- --nocapture 4 20 >> $logfile
cargo run --example tracing  -- --nocapture 4 25 >> $logfile



