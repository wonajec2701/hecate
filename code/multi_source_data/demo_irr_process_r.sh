#!/bin/bash

DATE=$1
# All data DATE is "0000-00-00"

log_file="/home/demo/multi_source_data/$DATE/execution_log.txt"
echo "$(date) IRR process started" >> "$log_file"
AllDataLog="/home/demo/multi_source_data/0000-00-00/execution_log.txt"
echo "$(date) IRR updates $DATE" > "$AllDataLog"
start_time_script1=$(date +%s)

cd /home/demo/multi_source_data/"$DATE"/irr_data
cp /home/demo/multi_source_data/ipv4_route_proc.py .
cp /home/demo/multi_source_data/ipv6_route6_proc.py .
rm -f db.routeuni db.route6uni
rm -f db.route.uni db.route6.uni

find . -type f -name "db.route" -exec sh -c 'cp "{}" "db.route.$(basename "$(dirname "{}")")"' \;
find . -type f -name "db.route6" -exec sh -c 'cp "{}" "db.route6.$(basename "$(dirname "{}")")"' \;

source_dir="/home/demo/multi_source_data/0000-00-00/irr_data"
destination_dir="/home/demo/multi_source_data/$DATE/irr_data"

if [ -d "$source_dir" ] && [ -d "$destination_dir" ]; then
    for file in "$destination_dir"/*; do
        if [[ "$file" == *db.route.* ]] || [[ "$file" == *db.route6.* ]]; then
            filename=$(basename "$file")
            find "$source_dir" -maxdepth 1 -type f -name "*$filename*" -delete
            cp -f "$file" "$source_dir/${file##*/}:$1"
        fi
    done
    for file in "$source_dir"/*; do
        if [[ "$file" == *:* ]]; then
            filename=$(basename "$file")
            filename_without_date="${filename%:*}"
            if ([[ "$file" == *db.route.* ]] || [[ "$file" == *db.route6.* ]]) && [ ! -f "$destination_dir/$filename_without_date" ]; then
                cp "$file" "$destination_dir/$filename_without_date"
            fi
        fi
    done
fi

SUFFIX=total
echo "$SUFFIX"
for file in "$destination_dir"/*; do
    if ([[ "$file" == *db.route.* ]]); then
        last_two_chars=$(tail -c 2 "$file")
        if [[ "$last_two_chars" != $'\n\n' ]]; then
        echo -e "\n" >> "$file"
        fi
    fi
done

find . -maxdepth 1 -type f -name "*db.route.*" -exec cat {} + > db.routeuni
find . -maxdepth 1 -type f -name "*db.route6.*" -exec cat {} + > db.route6uni
mv db.routeuni db.route.uni
mv db.route6uni db.route6.uni

python3 ipv4_route_proc.py
python3 ipv6_route6_proc.py
cp irr-route /home/demo/multi_source_data/cro_data/
cp irr-route6 /home/demo/multi_source_data/cro_data/
mv irr-route /home/demo/multi_source_data/"$DATE"/irr_data/irr-route-"$SUFFIX"-"$DATE"
mv irr-route6 /home/demo/multi_source_data/"$DATE"/irr_data/irr-route6-"$SUFFIX"-"$DATE"
rm db.route.uni db.route6.uni 
find . -maxdepth 1 -type f -name "*db.route*" -delete
rm ipv4_route_proc.py ipv6_route6_proc.py

end_time_script1=$(date +%s)
runtime_script1=$((end_time_script1 - start_time_script1))
echo "$(date) IRR process finished, used $runtime_script1 seconds" >> "$log_file"
