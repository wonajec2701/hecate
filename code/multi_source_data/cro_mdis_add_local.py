from source_analysis import getspemap, private_ip_list_v4, private_ip_list_v6
from cro_mdis_add import checkspeasn, checkspepfx
from datetime import datetime, timedelta
import sys
import os
current_directory = sys.argv[1]
check_day = int(sys.argv[2])
content = sys.argv[3]

def calculate_date(date_to_process, check_day):
    date_object = datetime.strptime(date_to_process, '%Y-%m-%d')
    bgpdate = []
    #  check_day 
    for i in range(check_day-1, -1, -1):
        result_date = date_object - timedelta(days=i)
        bgpdate.append(result_date.strftime('%Y%m%d'))
    print(bgpdate)
    return bgpdate


def clean_bgp(new_f, data, spemap_v4, spemap_v6, date_to_process, check_day, record_f):
    num = 0
    day_list = []
    bgpday = calculate_date(date_to_process, check_day)
    i = 0
    for day in bgpday:
        if content == '67':
            local_file_4 = day[0:4] + '-' + day[4:6] + '-' + day[6:8] + '/bgp_route/parsed-rib-ipv4'
            local_file_6 = day[0:4] + '-' + day[4:6] + '-' + day[6:8] + '/bgp_route/parsed-rib-ipv6'
            if not os.path.exists(local_file_4):
                continue
            f = open(local_file_4, 'r')
            for line in f:
                if '{' in line.split(' ')[0]:
                    continue
                try:
                    prefix = line.split(' ')[1]
                except:
                    print(line)
                    continue
                asn = int(line.split(' ')[0])
                pfx = prefix.split('/')[0]
                pl = int(prefix.split('/')[1].split('\n')[0])
                if prefix == '0.0.0.0/0' or prefix == '::/0':
                    continue
                if ':' in prefix and '.' in prefix:
                    continue
                if (prefix, asn) not in data:
                    data[(prefix, asn)] = {}
                    data[(prefix, asn)]['num'] = 1
                    data[(prefix, asn)]['day_list'] = [day]
                else:
                    data[(prefix, asn)]['num'] += 1
                    data[(prefix, asn)]['day_list'].append(day)
            f.close()
            if not os.path.exists(local_file_6):
                continue
            f = open(local_file_6, 'r')
            for line in f:
                if '{' in line.split(' ')[0]:
                    continue
                prefix = line.split(' ')[1]
                asn = int(line.split(' ')[0])
                pfx = prefix.split('/')[0]
                pl = int(prefix.split('/')[1].split('\n')[0])
                if prefix == '0.0.0.0/0' or prefix == '::/0':
                    continue
                if ':' in prefix and '.' in prefix:
                    continue
                if (prefix, asn) not in data:
                    data[(prefix, asn)] = {}
                    data[(prefix, asn)]['num'] = 1
                    data[(prefix, asn)]['day_list'] = [day]
                else:
                    data[(prefix, asn)]['num'] += 1
                    data[(prefix, asn)]['day_list'].append(day)
            f.close()
            num += 1

        

    f1 = open(new_f, 'w')
    f2 = open(record_f, 'w')
    f2.write(str(num) + '\n')
    
    num_record = 0
    for key, item in data.items():
        maxLength = int(key[0].split('/')[1])
        f2.write(str(key[1]) + ' ' + key[0] + ' ' + str(maxLength) + ' ' + str(len(set(item['day_list']))) + '\n')
        if len(set(item['day_list'])) >= num - 1 :
            f1.write(str(key[1]) + ' ' + key[0] + ' ' + str(maxLength) + '\n')
            num_record += 1
    
    f1.close()
    f2.close()
    
    return num, num_record


def read_rectification_cro(cro_file, new_cro_file, total_cro_file, spemap_v4, spemap_v6):
    num = 0
    if not os.path.exists(new_cro_file):
        f1.close()
        return 0
    f1 = open(cro_file, 'r')
    f2 = open(new_cro_file, 'r')
    f3 = open(total_cro_file, 'w')
    flag = 0
    for line in f1:
        if "asn" not in line:
            if flag == 0:
                f3.write(line)
            continue
        if flag == 0:
            flag = 1
        if flag == 1 and "asn" in line:
            f3.write(line)
            num += 1
        
    for line in f2:
        line_list = line.split(' ')
        try:
            prefix = str(line_list[1])
        except:
            continue
        asn = int(line_list[0])
        maxLength = int(line_list[2].split('\n')[0])
        pfx = prefix.split('/')[0]
        pl = int(prefix.split('/')[1].split('\n')[0])
        if ':' in prefix and checkspepfx(spemap_v6, pfx, pl)==True:
            continue
        if '.' in prefix and checkspepfx(spemap_v4, pfx, pl)==True:
            continue
        if checkspeasn(int(asn)) == True:
            continue
        if prefix == '0.0.0.0/0' or prefix == '::/0':
            continue
        if ':' in prefix and '.' in prefix:
            continue
        f3.write("{ \"asn\": \"AS" + str(asn) + "\", \"prefix\": \"" + prefix + "\", \"maxLength\": " + str(maxLength) + ", \"source\": [ { \"type\": \"BGP\", \"uri\": \"\", \"tal\": \"\", \"validity\": { \"notBefore\": \"\", \"notAfter\": \"\" }, \"chainValidity\": { \"notBefore\": \"\", \"notAfter\": \"\" } }] },\n")
        num += 1
        
    f1.close()
    f2.close()
    f3.close()
    return num

def to_cro(num, cfile):
    with open(cfile, 'r') as file:
        lines = file.readlines()

    # 
    if lines:
        # ，
        last_line = lines[-1].rstrip('\n,')  # 
        lines[-1] = last_line + '\n'

        lines[2] = '\"generated\": ' + str(num) + ',\n'

        # 
        with open(cfile, 'w') as file:
            file.writelines(lines)
            file.write("]}\n")

def main():
    
    start_time = datetime.now()
    start_timetamp = start_time.strftime("%Y%m%d %H:%M:%S")
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        log.write(f"{content}: {start_timetamp} generate local cro started\n")
    
    spemap_v4 = {}
    spemap_v6 = {}
    getspemap(spemap_v4, spemap_v6, private_ip_list_v4, private_ip_list_v6)

    data = {}
    num, num_record = clean_bgp(current_directory + '/bgp_filter_data/bgp_frequent_'+content, data, spemap_v4, spemap_v6, current_directory, check_day, current_directory + '/bgp_filter_data/bgp_frequency_'+content)
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        duration = finish_time - start_time
        log.write(f"{finish_timestamp} bgp filter ended, used {duration}\n")
        log.write(content + " bgp filter used " + str(num) + " days date, added " + str(num_record) + " records from " + str(len(data)) + " bgp routes.\n")
    
    cro_file = current_directory + '/cro_data/cro_mdis_' + current_directory
    if not os.path.exists(cro_file):
        cro_file = current_directory + '/cro_data/cro_mdis_initial_' + current_directory
    new_cro_file = current_directory + '/bgp_filter_data/bgp_frequent_'+content
    total_cro_file = current_directory + '/cro_data/cro_mdis_initial_' + current_directory + '_' + content
    num = read_rectification_cro(cro_file, new_cro_file, total_cro_file, spemap_v4, spemap_v6)
    to_cro(num, total_cro_file)

    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        duration = finish_time - start_time
        log.write(f"{content}: {finish_timestamp} generate local cro ended, used {duration}\n")

if __name__ == '__main__':
    main()
