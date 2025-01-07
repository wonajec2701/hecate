#!/bin/bash

current_date=$1 #$(date +%Y-%m-%d)

password="your-password"
dir="your-path"

mkdir -p "$dir/multi_source_data/$current_date"
log_file="$dir/multi_source_data/$current_date/execution_log.txt"
echo $password | sudo -S chmod 777 $log_file
echo "$(date) Execution started" >> "$log_file"
start_time=$(date +%s)


cd "$dir/multi_source_data/$current_date"
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
echo $password | sudo -S routinator --config=/etc/routinator/routinator.conf vrps -o "$current_date/roa_data/$current_date-0000" -f jsonext &

#download bgp route
python3 bgp_download_ripe.py "$current_date" &
python3 bgp_download_routeview.py "$current_date" &
python3 bgp_download_fiti.py "$current_date" &
wait

python3 bgp_jsoutput_separate.py "$current_date"

cp "$current_date/roa_data/$current_date-0000" roa_data/roa_data_now.json

REMOTE_DIR="$dir/multi_source_data/$current_date/bgp_route/parsed-rib-ipv6"
while [ ! -f "$REMOTE_DIR" ]; do
    sleep 1
done

#process bgp
echo $password | sudo -S python3 bgp_stable_filter_add_local.py "$current_date" 22
cp "$current_date/bgp_filter_data/bgp_frequency" cro_data/bgp_frequency

end_time=$(date +%s)
runtime=$((end_time - start_time))
echo "$(date) BGP Download finished, used $runtime seconds" >> "$log_file"
