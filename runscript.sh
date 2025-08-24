
today=`date +%Y-%m-%d_%H-%M-%S`
logfile=logfile_$today.txt
echo "Log file: $logfile"

#Arguments
#1 Batch size(B), Default value: 4
#2 Number of users(n), Default value: 8
#3 Code_constant, Default value: 10 
#3 Coalition size, Default value:(n/2) 

echo "For Table 3,5 batch size B = 128"  > $logfile
cargo run --example endtoend -- --nocapture 128 8 30 >> $logfile
cargo run --example endtoend -- --nocapture 128 16 10 >> $logfile
cargo run --example endtoend -- --nocapture 128 32 5 >> $logfile
cargo run --example endtoend -- --nocapture 128 64 5 >> $logfile

echo "For Table 4,6 number of parties n = 16" >> $logfile
cargo run --example endtoend -- --nocapture 8 16  10 >> $logfile
cargo run --example endtoend -- --nocapture 16 16 10 >> $logfile
cargo run --example endtoend -- --nocapture 32 16 10 >> $logfile
cargo run --example endtoend -- --nocapture 128 16 10 >> $logfile
cargo run --example endtoend -- --nocapture 512 16 10 >> $logfile




