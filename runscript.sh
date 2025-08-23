
today=`date +%Y-%m-%d_%H-%M-%S`
logfile=logfile_$today.txt
echo "Log file: $logfile"
echo "For Table 3, batch size B = 128"  > $logfile

cargo run --example endtoend -- --nocapture 128 8  >> $logfile
cargo run --example endtoend -- --nocapture 128 16 >> $logfile
cargo run --example endtoend -- --nocapture 128 32 >> $logfile

echo "For Table 4, number of parties n = 16" >> $logfile

cargo run --example endtoend -- --nocapture 8 16 >> $logfile
cargo run --example endtoend -- --nocapture 16 16 >> $logfile
cargo run --example endtoend -- --nocapture 32 16 >> $logfile



