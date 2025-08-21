#!/bin/bash
DATE=$1

log_file="/home/demo/multi_source_data/$DATE/execution_log.txt"
echo "$(date) IRR download started" >> "$log_file"
start_time_script1=$(date +%s)

main_dir="/home/demo/multi_source_data"

# Create a directory named by the current date
#cur_date=$1 #$(date +"%Y-%m-%d") 
cur_dir="$main_dir/$DATE/irr_data"
error_log="$cur_dir/error.log"

cd "$main_dir"

# Check if the "irr.list" file exists
if [ ! -f "irr.list" ]; then
  echo "The 'irr.list' file does not exist."
  exit 1
fi

# Run dl.sh for each URL in parallel using xargs
< "irr.list" xargs -P 40 -I {} ./demo_irr_dl.sh "{}" "$DATE"

echo "All downloads are complete." >> "$error_log"

end_time_script1=$(date +%s)
runtime_script1=$((end_time_script1 - start_time_script1))
echo "$(date) IRR download finished, used $runtime_script1 seconds" >> "$log_file"

./demo_irr_process_r.sh "$DATE"