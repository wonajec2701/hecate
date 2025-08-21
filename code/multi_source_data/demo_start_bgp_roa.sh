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
mkdir -p analysis
mkdir -p analysis/figure
mkdir -p analysis/result
cd ..


#download roa
routinator --config=/etc/routinator/routinator.conf vrps -o "$current_date/roa_data/$current_date-0000" -f jsonext &

#download bgp route
python3 bgp_download_ripe.py "$current_date" &
python3 bgp_download_routeview.py "$current_date" &
wait

python3 bgp_jsoutput_separate.py "$current_date"

cp "$current_date/roa_data/$current_date-0000" roa_data/roa_data_now.json

#process bgp
python3 bgp_stable_filter_add_local.py "$current_date" 22
cp "$current_date/bgp_filter_data/bgp_frequency" cro_data/bgp_frequency

./demo_download_caida.sh

end_time=$(date +%s)
runtime=$((end_time - start_time))
echo "$(date) BGP Download finished, used $runtime seconds" >> "$log_file"
