#!/bin/bash

today=$(date +%Y-%m-%d_%H-%M-%S)
logfile=logfile_trace_$today.txt
echo "Log file: $logfile"

{
printf "╔%s╗\n" "$(printf '═%.0s' {1..61})"
printf "║%-61s║\n" "       Traceable Batch Threshold Encryption — Tracing"
printf "╠%s╣\n" "$(printf '═%.0s' {1..61})"
printf "║  %-59s║\n" "Host    : $(hostname)"
printf "║  %-59s║\n" "CPU     : $(lscpu | grep 'Model name' | head -1 | sed 's/.*: *//' | cut -c1-57)"
printf "║  %-59s║\n" "Cores   : $(nproc) logical / $(lscpu | grep '^Core(s) per socket' | awk '{print $NF}') physical per socket"
printf "║  %-59s║\n" "RAM     : $(free -h | awk '/^Mem:/{print $2}') total"
printf "║  %-59s║\n" "OS      : $(uname -srm)"
printf "║  %-59s║\n" "Rust    : $(rustc --version)"
printf "║  %-59s║\n" "Date    : $(date '+%Y-%m-%d %H:%M:%S')"
printf "╚%s╝\n" "$(printf '═%.0s' {1..61})"
echo ""

#Arguments
#1 Batch size, input number in 2^b_power: 4,8,16,32,64,128,256
#2 Number of users(n), Default value: 8
#3 Code_constant, Default value: 10 , depends on n
#4 Coalition size, Default value: (n/2)

echo "── Varying batch size (fixed n=16, code_constant=10) ───────────────────────"
cargo run --example tracing -- --nocapture 4  16 10
cargo run --example tracing -- --nocapture 8  16 10
cargo run --example tracing -- --nocapture 16 16 10

echo ""
echo "── Varying users n (fixed batch=8) ─────────────────────────────────────────"
cargo run --example tracing -- --nocapture 8 8  30
cargo run --example tracing -- --nocapture 8 16 10
cargo run --example tracing -- --nocapture 8 24 5

} 2>&1 | tee -a $logfile
