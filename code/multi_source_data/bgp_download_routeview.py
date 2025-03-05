import sys
import os
import subprocess
import concurrent.futures
from datetime import datetime

date = sys.argv[1]
year, month, day = date.split('-')
current_directory = sys.argv[1]
routeview_file_path = os.path.join(current_directory, 'bgp_route', 'download', 'routeview')


collectors = [
    "decix.jhb", "route-views3", "route-views4", "route-views5", "route-views6", "decix.jhb",
    "route-views.amsix", "route-views.chicago", "route-views.chile", "route-views.eqix", "route-views.flix",
    "route-views.gorex", "route-views.isc", "route-views.kixp", "route-views.linx",
    "route-views.napafrica", "route-views.nwax", "pacwave.lax", "route-views.phoix", "route-views.telxatl",
    "route-views.wide", "route-views.sydney", "route-views2.saopaulo", "route-views.sg",
    "route-views.perth", "route-views.peru", "route-views.sfmix", "route-views.soxrs",
    "route-views.mwix", "route-views.rio", "route-views.fortaleza", "route-views.gixa", "route-views.bdix",
    "route-views.bknix", "route-views.uaeix", "route-views.ny"
]

urlp = 'http://archive.routeviews.org/'

def download_and_process_collector(c):
    y, m, d = int(year), int(month), int(day)
    filename = 'rib.%04d%02d%02d.0000.bz2' % (y, m, d)
    url = '%s/%s/bgpdata/%04d.%02d/RIBS/' % (urlp, c, y, m)
    temp_filename = c + '_' + filename
    new_name = '%s.rib.%04d%02d%02d.0000.bz2' % (c, y, m, d)
    outputfilename = 'bgpdump-output-%s.rib.%04d%02d%02d.0000.txt' % (c, y, m, d)
    print(outputfilename)
    
    if os.path.exists(outputfilename) and os.path.getsize(outputfilename) > 0:
        print(outputfilename + ' Exists.')
        return
    
    # Download the file to a temporary location
    subprocess.run(['wget', '-O', temp_filename, url + filename])

    cmd = 'bgpdump -m %s > %s' % (temp_filename, outputfilename)
    print(cmd)
    os.system(cmd)

    print("Remove " + temp_filename)
    os.remove(temp_filename)

def downloadrouteview():
    '''
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(download_and_process_collector, collectors)
    '''
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # 
        futures = {executor.submit(download_and_process_collector, c): c for c in collectors}
        
        # 30
        timeout_duration = timedelta(minutes=30)
        start_time = datetime.now()
        
        for future in concurrent.futures.as_completed(futures, timeout=timeout_duration.total_seconds()):
            collector_name = futures[future]
            try:
                future.result()  # ，（）
            except Exception as e:
                print(f"Error downloading from {collector_name}: {e}")
        
        # 
        if datetime.now() - start_time >= timeout_duration:
            print("，。")
            for future in futures:
                future.cancel()  # 

def main():
    start_time = datetime.now()
    start_timestamp = start_time.strftime("%Y%m%d %H:%M:%S")
    with open(f"{current_directory}/execution_log.txt", 'a') as log:
        log.write(f"{start_timestamp} Routeview download started\n")

    if not os.path.exists(routeview_file_path):
        os.makedirs(routeview_file_path)
    current_dir = os.getcwd()
    os.chdir(routeview_file_path)
    
    downloadrouteview()
    
    os.chdir(current_dir)

    finish_time = datetime.now()
    finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
    duration = finish_time - start_time
    with open(f"{current_directory}/execution_log.txt", 'a') as log:
        log.write(f"{finish_timestamp} Routeview download ended, used {duration}\n")

if __name__ == '__main__':
    main()