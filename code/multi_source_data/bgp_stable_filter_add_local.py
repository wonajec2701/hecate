from irr_filter import private_ip_list_v4, private_ip_list_v6, checkspepfx, checkspeasn
import numpy as np
import copy
from datetime import datetime, timedelta
import os
import sys
import time
import json


def getspemap(spemap_v4, spemap_v6, spelist_v4, spelist_v6):
    for prefix in spelist_v4:
        asns = 0
        pfx = prefix.split('/')[0]
        pfxlen = int(prefix.split('/')[1].split('\n')[0])
        createpfxmap(spemap_v4, asns, pfx, pfxlen)
    
    for prefix in spelist_v6:
        asns = 0
        pfx = prefix.split('/')[0]
        pfxlen = int(prefix.split('/')[1].split('\n')[0])
        createpfxmap(spemap_v6, asns, pfx, pfxlen)

def createpfxmap(pfxmap, asns, ip, pfxlen):
    length = int(pfxlen)
    #print(length)
    if length not in pfxmap:
        pfxmap[length] = {}
    pfxbin = getpfxbin(ip, length)
    if pfxbin not in pfxmap[length]:
        pfxmap[length][pfxbin] = {}
        s = pfxmap[length][pfxbin]
        s['prefix'] = [ip + '/' + str(pfxlen)]
        s['asns'] = [asns]
    #for asn in asns:
        #a.add(asn)
        #a.add(asns)
    else:
        s = pfxmap[length][pfxbin]
        s['prefix'].append(ip + '/' + str(pfxlen))
        s['asns'].append(asns)
    if s['prefix'] == '103.249.14.0/23':
        print(s['asns'])

def getpfxbin(pfx, length):
    pfxbinstr = ''
    temp = pfx
    """ IPv4 prefix """
    if '.' in pfx:
        pfx = pfx.split('.')
        for seg in pfx:
            try:
                segstr = bin(int(seg))[2:].zfill(8)
            except:
                print(temp)
            pfxbinstr += segstr
    """ IPv6 prefix """
    if ':' in pfx:
        pfx = pfx.split(':')
        pfxbinlist = []
        i = 0
        p = 0
        for seg in pfx:
            if seg == '':
                zsegstr = bin(0x0)[2:].zfill(16)
                p = i
            else:
                segstr = bin(int(seg, 16))[2:].zfill(16)
                i += 1
                pfxbinlist.append(segstr)
        z = 8 - i
        if z != 0:
            zsegstr = z*zsegstr
            pfxbinlist.insert(i, zsegstr)
        pfxbinstr = ''.join(pfxbinlist)

    return pfxbinstr[:length]

def extract_quoted_data(input_str):
    # 
    import re
    pattern = r"'(.*?)'"
    extracted_data = re.findall(pattern, input_str)    
    return extracted_data

def calculate_date(date_to_process, check_day):
    date_object = datetime.strptime(date_to_process, '%Y-%m-%d')
    bgpdate = []
    #  check_day 
    for i in range(check_day-1, -1, -1):
        result_date = date_object - timedelta(days=i)
        bgpdate.append(result_date.strftime('%Y%m%d'))
    print(bgpdate)
    return bgpdate

def clean_bgp(file_path, new_f, data, spemap_v4, spemap_v6, date_to_process, check_day, record_f, flag):
    num = 0
    day_list = []
    bgpday = calculate_date(date_to_process, check_day)
    i = 0
    for day in bgpday:
        i += 1
        file = day[0:4] + '-' + day[4:6] + '-' + day[6:8] + '/bgp_route/checklog/total/total-json-' + day + '-nopch.json'

        try:
            with open(file, 'r') as file:
                json_data = json.load(file)
        except:
            print(file)
            continue
        if len(json_data.get('routes', [])) == 1:
            continue
        
        day_list.append(i)
        num += 1

        #  "asn"  "Prefix" 
        for route in json_data.get('routes', []):
            asn = int(route.get('asn'))
            prefix = route.get('prefix')
            pfx = prefix.split('/')[0]
            pl = int(prefix.split('/')[1].split('\n')[0])
            '''
            if '.' in prefix and pl > 24:
                continue
            if ':' in prefix and pl > 48:
                continue
            '''
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
            if (prefix, asn) not in data:
                data[(prefix, asn)] = {}
                data[(prefix, asn)]['num'] = 1
                data[(prefix, asn)]['day_list'] = [day]
            else:
                data[(prefix, asn)]['num'] += 1
                data[(prefix, asn)]['day_list'].append(day)
       
        #local record add
        '''
        if flag == '67':
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


        '''
        

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

   


def main():
    start_time = time.time()
    args = sys.argv[1:]  # ignore the first arg, it's this file's name
    if len(args) > 2:
        print("Arg more than 1!")
        sys.exit(1)
    current_directory = args[0]
    date_to_process = current_directory
    check_day = int(args[1])
    starttime = datetime.now()
    start_timetamp = starttime.strftime("%Y%m%d %H:%M:%S")
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        log.write(f"{start_timetamp} bgp filter started\n")


    spemap_v4 = {}
    spemap_v6 = {}
    getspemap(spemap_v4, spemap_v6, private_ip_list_v4, private_ip_list_v6)


    data = {}
    
    #num, num_record = clean_bgp_cad('/home/cad/rpki/bgpdump/list/', current_directory + '/bgp_filter_data/bgp_frequent', data, spemap_v4, spemap_v6, current_directory, check_day, current_directory + '/bgp_filter_data/bgp_frequency')
    num, num_record = clean_bgp('', current_directory + '/bgp_filter_data/bgp_frequent', data, spemap_v4, spemap_v6, current_directory, check_day, current_directory + '/bgp_filter_data/bgp_frequency', 'None')
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        duration = finish_time - starttime
        log.write(f"{finish_timestamp} bgp filter ended, used {duration}\n")
        log.write("Default bgp filter used " + str(num) + " days date, added " + str(num_record) + " records from " + str(len(data)) + " bgp routes.\n")
    
    
if __name__ == '__main__':
    main()