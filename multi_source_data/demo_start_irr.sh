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
mkdir -p source_data
mkdir -p analysis
mkdir -p analysis/figure
mkdir -p analysis/result
cd ..

#download irr
echo $password | sudo -S ./demo_irr.sh $current_date

echo $password | sudo -S ./demo_irr_process_r.sh "$current_date"

datestamp=$(date +"%Y%m%d")
file_path="$dir/multi_source_data/$current_date/bgp_route/checklog/total/total-json-$datestamp.json"

while [ ! -f "$file_path" ]; do
    sleep 1
done

#process irr
echo $password | sudo -S python3 filter_irr.py "$current_date" 4 &
#process roa
echo $password | sudo -S python3 filter_roa.py "$current_date" 4 &
wait

file_path="$dir/multi_source_data/$current_date/bgp_filter_data/bgp_frequent"

while [ ! -f "$file_path" ]; do
    sleep 1
done

#process cro
python3 summarize_cro.py "$current_date"


echo $password | sudo -S python3 mdis_rov.py "$current_date" 0
echo $password | sudo -S python3 mdis_invalid.py "$current_date" 0
echo $password | sudo -S python3 mdis_path_filter.py "$current_date" 0
echo $password | sudo -S python3 mdis_analysis.py "$current_date" 0


# 定义文件路径
file_path="$dir/multi_source_data/$current_date/bgp_route/result/mdis_cro-$current_date"

if [ ! -f "$file_path" ]; then
    # 文件不存在，执行某操作，例如创建文件
    echo $password | sudo -S python3 mdis_analysis.py "$current_date" 0
fi


echo $password | sudo -S python3 cro_mdis_add.py "$current_date"

cp "$current_date/cro_data/cro_mdis_initial_$current_date" cro_data/cro_new_initial.json
cp "$current_date/cro_data/cro_mdis_$current_date" cro_data/cro_new.json


echo $password | sudo -S python3 mdis_analyze_fig.py "$current_date"
echo $password | sudo -S python3 mdis_analyze_invalid.py "$current_date"

echo $password | sudo -S ./demo_cro_web.sh "$current_date"



#process clean history data
echo $password | sudo -S python3 bgp_clean.py "$current_date" 7

end_time=$(date +%s)
runtime=$((end_time - start_time))
echo "$(date) Execution finished, used $runtime seconds" >> "$log_file"


#process aggregate
echo $password | sudo -S python3 generate_aggregate.py "$current_date"
