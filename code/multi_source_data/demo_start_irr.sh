#!/bin/bash

current_date=$(date +%Y-%m-%d)
mkdir -p "/home/demo/multi_source_data/$current_date"

log_file="/home/demo/multi_source_data/$current_date/execution_log.txt"
echo "$(date) Execution started" >> "$log_file"
start_time=$(date +%s)


cd "/home/demo/multi_source_data/$current_date"
mkdir -p irr_data
mkdir -p cro_data
mkdir -p bgp_route
mkdir -p roa_data
mkdir -p bgp_filter_data
mkdir -p source_data
mkdir -p analysis
mkdir -p analysis/figure
mkdir -p analysis/result
cd ..


#download irr
./demo_irr.sh $current_date

./demo_irr_process_r.sh "$current_date"

#IRR
datestamp=$(date +"%Y%m%d")  # ，yyyymmdd
file_path="/home/demo/multi_source_data/$current_date/bgp_route/checklog/total/total-json-$datestamp.json"
echo $file_path
while [ ! -f "$file_path" ]; do
    sleep 1
done
echo $file_path
#process irr
python3 filter_irr.py "$current_date" 4 &
#process roa
python3 filter_roa.py "$current_date" 4 &
wait

#cro
file_path="/home/demo/multi_source_data/$current_date/bgp_filter_data/bgp_frequent"

while [ ! -f "$file_path" ]; do
    sleep 1
done

#process cro
python3 summarize_cro.py "$current_date"

python3 mdis_rov.py "$current_date" 0 "None"
python3 mdis_invalid.py "$current_date" 0 "None"
python3 mdis_path_filter.py "$current_date" 0 "None"
python3 mdis_analysis.py "$current_date" 0 "None"
python3 cro_mdis_add.py "$current_date" "None"
cp "$current_date/cro_data/cro_mdis_initial_$current_date" cro_data/cro_new_initial.json
cp "$current_date/cro_data/cro_mdis_$current_date" cro_data/cro_new.json

#local record
python3 cro_mdis_add_local.py "$current_date" 22 "67"

python3 mdis_analyze_fig.py "$current_date"


#process clean history data
python3 bgp_clean.py "$current_date" 7


end_time=$(date +%s)
runtime=$((end_time - start_time))
echo "$(date) Execution finished, used $runtime seconds" >> "$log_file"


#process aggregate
python3 generate_aggregate.py "$current_date" "None"