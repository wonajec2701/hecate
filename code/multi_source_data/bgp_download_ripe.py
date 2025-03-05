import sys
import os
import concurrent.futures
import subprocess
import time
from datetime import datetime, timedelta

date = sys.argv[1]
year = date.split('-')[0]
month = date.split('-')[1]
day = date.split('-')[2]
current_directory = sys.argv[1]
ripe_file_path = current_directory + '/bgp_route/download/ripe_ris'

collectors = ['rrc00', 'rrc01', 'rrc03', 'rrc04', 'rrc05', 'rrc06',
              'rrc07', 'rrc10', 'rrc11', 'rrc12', 'rrc13',
              'rrc14', 'rrc15', 'rrc16', 'rrc18', 'rrc19',
              'rrc20', 'rrc21', 'rrc22', 'rrc23', 'rrc24', 'rrc25', 'rrc26']

urlp = 'https://data.ris.ripe.net'

# download static route table
y = int(year)
m = int(month)
d = int(day)

def download_and_process_collector(c):
    filename = 'bview.%04d%02d%02d.0000.gz' % (y, m, d)
    url = '%s/%s/%04d.%02d/%s' % (urlp, c, y, m, filename)
    temp_filename = c + '_' + filename
    outputfilename = 'bview.%04d%02d%02d.0000.%s.txt' % (y, m, d, c)
    
    if os.path.exists(outputfilename):
        return
    
    # Download the file to a temporary location
    subprocess.run(['wget', '-O', temp_filename, url])
    
    # Run bgpdump and redirect the output to the desired output file
    cmd = 'bgpdump -m %s > %s' % (temp_filename, outputfilename)
    print(cmd)
    os.system(cmd)
    
    # Remove the temporary file
    os.remove(temp_filename)

def downloadripe():
    '''
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(download_and_process_collector, collectors)
    '''
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(download_and_process_collector, c): c for c in collectors}
        
        timeout_duration = timedelta(minutes=30)
        start_time = datetime.now()
        
        for future in concurrent.futures.as_completed(futures, timeout=timeout_duration.total_seconds()):
            collector_name = futures[future]
            try:
                future.result() 
            except Exception as e:
                print(f"Error downloading from {collector_name}: {e}")
        
        if datetime.now() - start_time >= timeout_duration:
            print("，。")
            for future in futures:
                future.cancel()  

def main():
    start_time = datetime.now()
    start_timetamp = start_time.strftime("%Y%m%d %H:%M:%S")
    with open(f"{current_directory}/execution_log.txt", 'a') as log:
        log.write(f"{start_timetamp} RIPE download started\n")
    
    if not os.path.exists(ripe_file_path):
        os.makedirs(ripe_file_path)
    current_dir = os.getcwd()
    os.chdir(ripe_file_path)
    downloadripe()
    os.chdir(current_dir)
    
    with open(f"{current_directory}/execution_log.txt", 'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        duration = finish_time - start_time
        log.write(f"{finish_timestamp} RIPE download ended, used {duration}\n")

if __name__ == '__main__':
    main()