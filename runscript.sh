#!/bin/bash

today=$(date +%Y-%m-%d_%H-%M-%S)
logfile=logfile_$today.txt
echo "Log file: $logfile"

{
printf "╔%s╗\n" "$(printf '═%.0s' {1..61})"
printf "║%s║\n" "$(printf '%61s' '' | tr ' ' ' ')"; printf "║%-61s║\n" "       Traceable Batch Threshold Encryption — Benchmarks"
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
#1 Batch size(B), Default value: 4
#2 Number of users(n), Default value: 8
#3 Code_constant, Default value: 10
#4 Coalition size, Default value: (n/2)

echo "── Table: varying batch size B (n=8..64, fixed code structure) ──────────────"
cargo run --example endtoend -- --nocapture 128 8 30
cargo run --example endtoend -- --nocapture 128 16 10
cargo run --example endtoend -- --nocapture 128 32 5
cargo run --example endtoend -- --nocapture 128 64 5

echo ""
echo "── Table: varying batch size B (n=16 fixed) ────────────────────────────────"
cargo run --example endtoend -- --nocapture 8   16 10
cargo run --example endtoend -- --nocapture 16  16 10
cargo run --example endtoend -- --nocapture 32  16 10
cargo run --example endtoend -- --nocapture 128 16 10
cargo run --example endtoend -- --nocapture 512 16 10

} 2>&1 | tee -a $logfile
