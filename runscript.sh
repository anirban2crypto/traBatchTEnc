
today=`date +%Y-%m-%d_%H-%M-%S`
logfile=logfile_$today.txt
echo "Log file: $logfile"

echo "For Table 3,5 batch size B = 128"  > $logfile
cargo run --example endtoend -- --nocapture 128 8  >> $logfile
cargo run --example endtoend -- --nocapture 128 16 >> $logfile
cargo run --example endtoend -- --nocapture 128 32 >> $logfile
cargo run --example endtoend -- --nocapture 128 64 >> $logfile

echo "For Table 4,6 number of parties n = 16" >> $logfile
cargo run --example endtoend -- --nocapture 8 16 >> $logfile
cargo run --example endtoend -- --nocapture 16 16 >> $logfile
cargo run --example endtoend -- --nocapture 32 16 >> $logfile
cargo run --example endtoend -- --nocapture 128 16 >> $logfile
cargo run --example endtoend -- --nocapture 512 16 >> $logfile




