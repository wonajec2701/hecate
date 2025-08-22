#!/bin/bash

yesterday=$(date -d "yesterday" +"%Y-%m-%d")
current_date=$(date +%Y-%m-%d)
echo $current_date
mkdir -p "/home/demo/route_analyze/$current_date"

log_file="/home/demo/route_analyze/$current_date/execution_log.txt"
echo "$(date) demo_local Execution started" >> "$log_file"
start_time=$(date +%s)


cd "/home/demo/route_analyze/$current_date"
mkdir -p cro_data
mkdir -p bgp_route
mkdir -p source_data
mkdir -p collaboration_data
cd ..

content="local"
echo "$(date), Local Start" >> "$log_file"

cp "/home/demo/multi_source_data/$current_date/source_data/roa_aggregate_$current_date"  cro_data/cro_aggregate
cp "/home/demo/multi_source_data/$current_date/source_data/roa_aggregate_$current_date" "$current_date/source_data/roa_aggregate_$current_date"
cp "/home/demo/multi_source_data/$yesterday/source_data/roa_aggregate_$yesterday" "$yesterday/source_data/roa_aggregate_$yesterday"
python3 generate_invalid_unknown.py $current_date $content $yesterday
python3 route_retification.py $current_date $content $yesterday

end_time=$(date +%s)
runtime=$((end_time - start_time))
echo "$(date) Execution finished, used $runtime seconds" >> "$log_file"
