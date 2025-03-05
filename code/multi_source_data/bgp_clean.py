from datetime import datetime, timedelta
import sys
import os



def calculate_date(date_to_process, check_day):
    date_object = datetime.strptime(date_to_process, '%Y-%m-%d')
    result_date = date_object - timedelta(days=check_day)
    return result_date.strftime('%Y-%m-%d')

def delete(path, current_dir):
    if os.path.exists(path):
        os.chdir(path)
        cmd = 'rm -r *'
        os.system(cmd)
        os.chdir(current_dir)

def main():
    args = sys.argv[1:]  # ignore the first arg, it's this file's name
    if len(args) > 2:
        print("Arg more than 1!")
        sys.exit(1)
    current_directory = args[0]
    date_to_process = current_directory
    check_day = int(args[1])
    clean_day = calculate_date(date_to_process, check_day)
    print(clean_day)

    current_dir = os.getcwd()
    delete(clean_day + '/bgp_route/download', current_dir)
    delete(clean_day + '/bgp_route/as-set', current_dir)
    delete(clean_day + '/bgp_route/analysis', current_dir)
    delete(clean_day + '/bgp_route/list', current_dir)
    delete(clean_day + '/bgp_route/checklog/valid', current_dir)
    delete(clean_day + '/bgp_route/checklog/unknown', current_dir)
    delete(clean_day + '/bgp_route/checklog/invalid', current_dir)
    delete(clean_day + '/irr_data/irrraw', current_dir)
    #delete(clean_day + '/bgp_route/run-log', current_dir)
    irr_list = ['afrinic', 'altdb', 'apnic', 'arin', 'bboi', 'bell', 'canarie', 'idnic', 'jpirr', 'jpnic', 'krnic', 'lacnic', 'level3', 'nestegg', 'nttcom', 'panix', 'radb', 'reach', 'ripe-nonauth', 'ripe', 'tc', 'twnic']
    #for i in irr_list:
        #delete(clean_day + '/irr_data/'+i, current_dir)

    
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        log.write(f"{finish_timestamp} BGP clean ended.\n")


if __name__ == '__main__':
    main()