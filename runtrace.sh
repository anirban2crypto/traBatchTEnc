#!/bin/bash

today=`date +%Y-%m-%d_%H-%M-%S`
logfile=logfile_trace_$today.txt
echo "Log file: $logfile"



#Arguments
#1 Batch size, input number in 2^b_power: 4,8,16,32,64,128,256
#2 Number of users(n), Default value: 8
#3 Code_constant, Default value: 10 
#4 Coalition size, Default value: (n/2) 

cargo run --example tracing  -- --nocapture 4  16 10  >> $logfile
cargo run --example tracing  -- --nocapture 12 16 10  >> $logfile
cargo run --example tracing  -- --nocapture 16 16 10  >> $logfile


cargo run --example tracing  -- --nocapture 8 8  30  >> $logfile
cargo run --example tracing  -- --nocapture 8 16 10  >> $logfile
cargo run --example tracing  -- --nocapture 8 24 5  >> $logfile








