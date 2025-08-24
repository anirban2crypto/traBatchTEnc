#!/bin/bash

today=`date +%Y-%m-%d_%H-%M-%S`
logfile=logfile_trace_$today.txt
echo "Log file: $logfile"

# Batch size, selected randomly as 2^b_power, where b_power is in [1,3]

#Arguments
#1 Number of users(n), Default value: 8
#2 Code_constant, Default value: 10 
#3 Coalition size, Default value: (n/2) 


cargo run --example tracing  -- --nocapture 8 30  >> $logfile
cargo run --example tracing  -- --nocapture 12 20 >> $logfile
cargo run --example tracing  -- --nocapture 16 10  >> $logfile
cargo run --example tracing  -- --nocapture 20 10  >> $logfile



