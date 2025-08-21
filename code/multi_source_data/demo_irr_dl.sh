#!/bin/bash

# Define the main directory
DATE=$2
main_dir="/home/demo/multi_source_data"

# Create a directory named by the current date
cur_dir="$main_dir/$DATE/irr_data"
error_log="$cur_dir/error.log"
touch "$error_log"
#mkdir -p "$cur_dir"

# Navigate to the current directory
cd "$cur_dir"

# Input parameter: URL of the file
file_url="$1"
file_name=$(basename "$file_url")
#echo "filename is $file_name"
irr_name="${file_name%%.*}"
output_dir="$cur_dir/$irr_name"
# Check if db is split correctly already by checking if output_dir is empty
if [ -d "$output_dir" ]; then
    echo "db is split correctly already!"
    exit 0
  fi

# Calculate the hash value of the URL
hash_value=$(echo -n "$file_url" | sha256sum | awk '{print $1}')
# Create a temp directory named by the hash value and download the file into it 
hash_dir="$cur_dir/$hash_value"
mkdir -p "$hash_dir"

timestamp=$(date +"%Y-%m-%d %H:%M:%S")
echo "[$timestamp] Start downloading: $file_url" >> "$error_log"

if wget --inet4-only "$file_url" -P "$hash_dir"; then
  timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  echo "[$timestamp] Successfully download: $file_url" >> "$error_log"
else
  timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  echo "[$timestamp] Error downloading: $file_url" >> "$error_log"
  rm -rf "$hash_dir"
  exit 1
fi

echo "file downloaded !"

# Decompress the file

if gunzip -f -c "$hash_dir/$file_name" > "$hash_dir/$irr_name.db"; then
  #print out db file size
  du -h "$hash_dir/$irr_name.db" >> "$error_log"
  # Create a directory named by irr_name  
  mkdir -p "$output_dir"
  # Split db by type
  python3 "$main_dir"/split_db_by_type.py "$hash_dir/$irr_name.db" "$output_dir"
  rm -rf "$hash_dir"
  # output_dir is not empty means db is split correctly
  if [ "$(ls -A "$output_dir")" ]; then
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] Output files saved in '$output_dir'" >> "$error_log"
    exit 0
  else
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] File fails to split in '$output_dir'" >> "$error_log"
    rm -rf "$output_dir"
    exit 1
  fi
  
else
  echo "Wrongly unzip $file_name"
  rm -rf "$hash_dir"
  exit 1

fi

