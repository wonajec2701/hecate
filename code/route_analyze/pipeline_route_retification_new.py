from source_analysis import checkspepfx, checkspeasn, private_ip_list_v4, private_ip_list_v6
from source_analysis import getspemap, getroamap, getpfxmap, getpfxbin
from datetime import date, datetime

import os
import json
import time
import copy
import threading

cro_file = '/home/demo/multi_source_data/cro_data/cro_new.json'
roa_file = '/home/demo/multi_source_data/roa_data/roa_data_now.json'
cro_aggregate_file = '/home/demo/route_analyze/cro_data/cro_aggregate'
irr4_file = '/home/demo/multi_source_data/cro_data/irr-route'
irr6_file = '/home/demo/multi_source_data/cro_data/irr-route6'
bgp_frequency_file = '/home/demo/multi_source_data/cro_data/bgp_frequency'
bgp_current_file = '/home/demo/multi_source_data/cro_data/bgp_current'
asrel_file = '/home/demo/multi_source_data/CAIDA/relationship/as-rel2.txt'
as2org_file = '/home/demo/multi_source_data/CAIDA/as_org/as-org2info.jsonl'
similar_as2org_file = '/home/demo/multi_source_data/CAIDA/as_org/similar_as_org'

non_valid_file = 'current-total-with-path'

new_file = '/home/demo/multi_source_data/cro_data/cro_new_route_add.json'
route_add_file = '/home/demo/route_analyze/cro_data/valid_local'



data_cro = {}
cromap_v4 = {}
cromap_v6 = {}
data_cro_asn = {}

data_real_roa = {}
real_roamap_v4 = {}
real_roamap_v6 = {}

roamap_v4 = {}
roamap_v6 = {}
data_aggregate = {}
data_irr = {}
irrmap_v4 = {}
irrmap_v6 = {}
data_bgp_current = {}
data_bgp_currentmap_v4 = {}
data_bgp_currentmap_v6 = {}
max_bgp_day = 0
data_bgp_total = {}
asrel = {}
asrel_cus = {}
data_as_country = {}
as2org = {}
similar_as = {}

mod_time_cro = 0
mod_time_roa = 0
mod_time_cro_aggregate = 0
mod_time_irr = 0
mod_time_bgp = 0
mod_time_bgp_current = 0
mod_time_asrel = 0
mod_time_as2org = 0
mod_time_similar_as2org = 0
mod_time_non_valid = 0


lock_cro = threading.Lock()
lock_roa = threading.Lock()
lock_cro_aggregate = threading.Lock()
lock_irr = threading.Lock()
lock_bgp_day = threading.Lock()
lock_bgp = threading.Lock()
lock_bgp_current = threading.Lock()
lock_asrel = threading.Lock()
lock_as2org = threading.Lock()
lock_route_add = threading.Lock()
lock_record = threading.Lock()
lock_record_invalid = threading.Lock()
lock_record_unknown = threading.Lock()

def read_CRO(file):
    global mod_time_cro
    while True:
        try:
            current_mod_time = os.path.getmtime(file)
            if current_mod_time != mod_time_cro:
                data_cro_temp = {}
                data_cro_asn_temp = {}
                cromap_v4_temp = {}
                cromap_v6_temp = {}
                f1 = open(file, 'r')
                print(file)
                for line in f1:
                    if "asn" not in line:
                        continue
                    asn = int(line.split("asn\": \"")[1].split("\"")[0][2:])
                    prefix = line.split("prefix\": \"")[1].split("\"")[0]
                    maxLength = int(line.split("maxLength\": ")[1].split(",")[0])
                    ty_pe = line.split("type\": \"")[1].split("\"")[0]

                    if (prefix, asn, maxLength) not in data_cro_temp:
                        data_cro_temp[(prefix, asn, maxLength)] = {}
                        data_cro_temp[(prefix, asn, maxLength)]['source'] = ty_pe
                        data_cro_temp[(prefix, asn, maxLength)]['valid'] = []
                        data_cro_temp[(prefix, asn, maxLength)]['invalid'] = []
                    
                    if asn not in data_cro_asn_temp:
                        data_cro_asn_temp[asn] = {}
                        data_cro_asn_temp[asn][maxLength] = [prefix]
                    else:
                        if maxLength not in data_cro_asn_temp[asn]:
                            data_cro_asn_temp[asn][maxLength] = [prefix]
                        else:
                            data_cro_asn_temp[asn][maxLength].append(prefix)

                f1.close()
                with lock_cro:
                    global data_cro, data_cro_asn, cromap_v4, cromap_v6
                    data_cro = copy.deepcopy(data_cro_temp)
                    data_cro_asn = copy.deepcopy(data_cro_asn_temp)
                    getroamap(cromap_v4_temp, cromap_v6_temp, data_cro)
                    cromap_v4 = copy.deepcopy(cromap_v4_temp)
                    cromap_v6 = copy.deepcopy(cromap_v6_temp)
                mod_time_cro = current_mod_time
                print(f"File {file} has updated.")
        except FileNotFoundError:
            print(f"File {file} not found.")
        time.sleep(60) 


def read_ROA(file):
    global mod_time_roa
    while True:
        try:
            current_mod_time = os.path.getmtime(file)
            if current_mod_time != mod_time_roa:
                data_roa_temp = {}
                roamap_v4_temp = {}
                roamap_v6_temp = {}
                f1 = open(file, 'r')
                print(file)
                for line in f1:
                    if "asn" not in line:
                        continue
                    asn = int(line.split("asn\": \"")[1].split("\"")[0][2:])
                    prefix = line.split("prefix\": \"")[1].split("\"")[0]
                    maxLength = int(line.split("maxLength\": ")[1].split(",")[0])
                    ty_pe = line.split("type\": \"")[1].split("\"")[0]

                    if (prefix, asn, maxLength) not in data_roa_temp:
                        data_roa_temp[(prefix, asn, maxLength)] = {}
                        data_roa_temp[(prefix, asn, maxLength)]['source'] = ty_pe
                        data_roa_temp[(prefix, asn, maxLength)]['valid'] = []
                        data_roa_temp[(prefix, asn, maxLength)]['invalid'] = []
                    
                f1.close()
                with lock_roa:
                    global data_real_roa, real_roamap_v4, real_roamap_v6
                    data_real_roa = copy.deepcopy(data_roa_temp)
                    getroamap(roamap_v4_temp, roamap_v6_temp, data_real_roa)
                    real_roamap_v4 = copy.deepcopy(roamap_v4_temp)
                    real_roamap_v6 = copy.deepcopy(roamap_v6_temp)
                mod_time_roa = current_mod_time
                print(f"File {file} has updated.")
        except FileNotFoundError:
            print(f"File {file} not found.")
        time.sleep(60) 

def read_roa_aggregate(file):
    global mod_time_cro_aggregate
    while True:
        try:
            current_mod_time = os.path.getmtime(file)
            if current_mod_time != mod_time_cro_aggregate:
                data_aggregate_temp = {}
                roamap_v4_temp = {}
                roamap_v6_temp = {}
                f2 = open(file, 'r')
                for line in f2:
                    line_list = line.split(' ')
                    try:
                        prefix = str(line_list[1])
                        asn = int(line_list[0])
                        maxLength = int(line_list[2])
                        if (prefix, asn, maxLength) not in data_aggregate_temp:
                            data_aggregate_temp[(prefix, asn, maxLength)] = {}
                            data_aggregate_temp[(prefix, asn, maxLength)]['type'] = ['roa_aggregate']
                    except:
                        continue
                f2.close()
                with lock_cro_aggregate:
                    global data_aggregate, roamap_v4, roamap_v6
                    data_aggregate = copy.deepcopy(data_aggregate_temp)
                    getroamap(roamap_v4_temp, roamap_v6_temp, data_aggregate)
                    roamap_v4 = copy.deepcopy(roamap_v4_temp)
                    roamap_v6 = copy.deepcopy(roamap_v6_temp)
                mod_time_cro_aggregate = current_mod_time
                print(f"File {file} has updated.")
        except FileNotFoundError:
            print(f"File {file} not found.")
        time.sleep(60) 

def process_irr(file4, file6, spemap_v4, spemap_v6):
    global mod_time_irr
    while True:
        try:
            current_mod_time = os.path.getmtime(file4)
            if current_mod_time != mod_time_irr:
                data_irr_temp = {}
                irrmap_v4_temp = {}
                irrmap_v6_temp = {}
                f1 = open(file4, 'r', encoding = "ISO-8859-1")
                for line in f1:
                    try:
                        prefix = line.split(' ')[1]
                    except:
                        continue
                    try:
                        asn = int(line.split(' ')[0])
                    except:
                        continue
                    pfx = prefix.split('/')[0]
                    try:
                        pl = int(prefix.split('/')[1])
                    except:
                        continue
                    if ':' in pfx and checkspepfx(spemap_v6, pfx, pl)==True:
                        continue
                    if '.' in pfx and checkspepfx(spemap_v4, pfx, pl)==True:
                        continue
                    if checkspeasn(asn) == True:
                        continue
                    if prefix == '0.0.0.0/0' or prefix == '::/0':
                        continue
                    maxlen = pl
                    if (prefix, asn, maxlen) not in data_irr_temp:
                        data_irr_temp[(prefix, asn, maxlen)] = {}
                        data_irr_temp[(prefix, asn, maxlen)]['num'] = 1
                        data_irr_temp[(prefix, asn, maxlen)]['valid'] = []
                        data_irr_temp[(prefix, asn, maxlen)]['invalid'] = []
                    else:
                        data_irr_temp[(prefix, asn, maxlen)]['num'] += 1
                f1.close()
                f1 = open(file6, 'r', encoding = "ISO-8859-1")
                for line in f1:
                    try:
                        prefix = line.split(' ')[1]
                    except:
                        continue
                    try:
                        asn = int(line.split(' ')[0])
                    except:
                        continue
                    pfx = prefix.split('/')[0]
                    try:
                        pl = int(prefix.split('/')[1])
                    except:
                        continue
                    if ':' in pfx and checkspepfx(spemap_v6, pfx, pl)==True:
                        continue
                    if '.' in pfx and checkspepfx(spemap_v4, pfx, pl)==True:
                        continue
                    if checkspeasn(asn) == True:
                        continue
                    if prefix == '0.0.0.0/0' or prefix == '::/0':
                        continue
                    maxlen = pl
                    if (prefix, asn, maxlen) not in data_irr_temp:
                        data_irr_temp[(prefix, asn, maxlen)] = {}
                        data_irr_temp[(prefix, asn, maxlen)]['num'] = 1
                        data_irr_temp[(prefix, asn, maxlen)]['valid'] = []
                        data_irr_temp[(prefix, asn, maxlen)]['invalid'] = []
                    else:
                        data_irr_temp[(prefix, asn, maxlen)]['num'] += 1
                f1.close()
                with lock_irr:
                    global data_irr, irrmap_v4, irrmap_v6
                    data_irr = copy.deepcopy(data_irr_temp)
                    getroamap(irrmap_v4_temp, irrmap_v6_temp, data_irr)
                    irrmap_v4 = copy.deepcopy(irrmap_v4_temp)
                    irrmap_v6 = copy.deepcopy(irrmap_v6_temp)

                mod_time_irr = current_mod_time
                print(f"File {file4} has updated.")
        except FileNotFoundError:
            print(f"File {file4} not found.")
        time.sleep(60) 

def process_bgp_current(file, spemap_v4, spemap_v6):
    global mod_time_bgp_current
    while True:
        try:
            current_mod_time = os.path.getmtime(file)
            if current_mod_time != mod_time_bgp_current:
                data_bgp_current_temp = {}
                data_bgp_currentmap_v4_temp = {}
                data_bgp_currentmap_v6_temp = {}
                with open(file, 'r') as f:
                    json_data = json.load(f)
                for route in json_data.get('routes', []):
                    asn = int(route.get('asn'))
                    prefix = route.get('prefix')
                    pfx = prefix.split('/')[0]
                    pl = int(prefix.split('/')[1].split('\n')[0])
                    
                    if '.' in prefix and pl > 24:
                        continue
                    if ':' in prefix and pl > 48:
                        continue
                    
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
                    if (prefix, asn) not in data_bgp_current_temp:
                        data_bgp_current_temp[(prefix, asn)] = 0
                
                getpfxmap(data_bgp_currentmap_v4_temp, data_bgp_currentmap_v6_temp, data_bgp_current_temp)
                with lock_bgp:
                    global data_bgp_current, data_bgp_currentmap_v4, data_bgp_currentmap_v6
                    data_bgp_current = copy.deepcopy(data_bgp_current_temp)
                    data_bgp_currentmap_v4 = copy.deepcopy(data_bgp_currentmap_v4_temp)
                    data_bgp_currentmap_v6 = copy.deepcopy(data_bgp_currentmap_v6_temp)
                mod_time_bgp_current = current_mod_time
                leng = len(data_bgp_currentmap_v6)
                print(f"File {file} has updated, {leng}")
        except FileNotFoundError:
            print(f"File {file} not found.")
        time.sleep(60)


def process_bgp_total(file):
    global mod_time_bgp
    while True:
        try:
            current_mod_time = os.path.getmtime(file)
            if current_mod_time != mod_time_bgp:
                data_bgp_total_temp = {}
                f2 = open(file, 'r')
                i = 0
                for line in f2:
                    if i == 0:
                        i = 1
                        with lock_bgp_day:
                            global max_bgp_day
                            max_bgp_day = int(line.split('\n')[0])
                        continue
                    line_list = line.split(' ')
                    prefix = line_list[1]
                    asn = int(line_list[0])
                    day = int(line_list[3].split('\n')[0])
                    if (prefix, asn) not in data_bgp_total_temp:
                        data_bgp_total_temp[(prefix, asn)] = day
                with lock_bgp:
                    global data_bgp_total
                    data_bgp_total = copy.deepcopy(data_bgp_total_temp)
                mod_time_bgp = current_mod_time
                print(f"File {file} has updated.")
        except FileNotFoundError:
            print(f"File {file} not found.")
        time.sleep(60) 

def process_asrel(file):
    global mod_time_asrel
    while True:
        try:
            current_mod_time = os.path.getmtime(file)
            if current_mod_time != mod_time_asrel:
                asrel_temp = {}
                asrel_cus_temp = {}
                f1 = open(file, 'r', encoding = "ISO-8859-1")
                for line in f1:
                    if '#' in line:
                        continue
                    temp = line.split('|')
                    asrel_temp[(int(temp[0]), int(temp[1]))] = int(temp[2].split('\n')[0])
                    if int(temp[2].split('\n')[0]) != -1:
                        continue
                    if int(temp[0]) not in asrel_cus_temp:
                        asrel_cus_temp[int(temp[0])] = {}
                        asrel_cus_temp[int(temp[0])]['customer'] = [int(temp[1])]
                        asrel_cus_temp[int(temp[0])]['provider'] = []
                    else:
                        asrel_cus_temp[int(temp[0])]['customer'].append(int(temp[1]))
                        
                    if int(temp[1]) not in asrel_cus_temp:
                        asrel_cus_temp[int(temp[1])] = {}
                        asrel_cus_temp[int(temp[1])]['customer'] = []
                        asrel_cus_temp[int(temp[1])]['provider'] = [int(temp[0])]
                    else:
                        asrel_cus_temp[int(temp[1])]['provider'].append(int(temp[0]))
                with lock_asrel:
                    global asrel, asrel_cus
                    asrel = copy.deepcopy(asrel_temp)
                    asrel_cus = copy.deepcopy(asrel_cus_temp)
                mod_time_asrel = current_mod_time
                print(f"File {file} has updated.")
        except FileNotFoundError:
            print(f"File {file} not found.")
        time.sleep(60)

def process_as_country(caida_file, as2org, org2country):
    f = open(caida_file, 'r')
    for line in f:
        if '\"asn\":' in line:
            asn = int(line.split('\"asn\":\"')[1].split('\"')[0])
            org = line.split('\"organizationId\":\"')[1].split('\"')[0]
            if asn not in as2org:
                as2org[asn] = org
        if '\"country\":' in line:
            country = line.split('\"country\":\"')[1].split('\"')[0]
            org = line.split('\"organizationId\":\"')[1].split('\"')[0]
            if org not in org2country:
                org2country[org] = country
                
def process_as2org(caida_file):
    global mod_time_as2org
    while True:
        try:
            current_mod_time = os.path.getmtime(caida_file)
            if current_mod_time != mod_time_as2org:
                data_as_country_temp = {}
                as2org_temp = {}
                
                org2country = {}
                process_as_country(caida_file, as2org_temp, org2country)
                for asn in as2org_temp:
                    data_as_country_temp[asn] = org2country[as2org_temp[asn]]
            
                with lock_as2org:
                    global data_as_country, as2org
                    data_as_country = copy.deepcopy(data_as_country_temp)
                    as2org = copy.deepcopy(as2org_temp)
                mod_time_as2org= current_mod_time
                print(f"File {caida_file} has updated.")
        except FileNotFoundError:
            print(f"File {caida_file} not found.")
        time.sleep(60)

def rovproc_cro_single(roamap, pfx, length, asnset, pfxstr, data_nonvalid, data_cro):
    r = 'unknown'
    pfx_exists = False
    invalid_list = []
    for pl in range(length, -1, -1):
        if pl not in roamap:
            continue
        t = pfx[:pl]
        if t in roamap[pl]:
            pfx_exists = True
            vrpset = roamap[pl][t]
            n = vrpset['num']
            vrps = vrpset['vrps']
            for i in range(n):
                v = vrps[i]
                maxlen = v['maxlen']
                asn = v['asn']
                if length <= maxlen and asn == asnset:
                    r = 'valid'
                elif asn != asnset:
                    invalid_list.append('invalid_asn')
                    data_nonvalid[(pfxstr, asnset)]['detail'].append([v['vrp'], asn, maxlen, data_cro[(v['vrp'], asn, maxlen)]['source']])
                else:
                    invalid_list.append('invalid_maxlen')
                    data_nonvalid[(pfxstr, asnset)]['detail'].append([v['vrp'], asn, maxlen, data_cro[(v['vrp'], asn, maxlen)]['source']])
                    
    
    if pfx_exists and r!= 'valid':
        if 'invalid_asn' in invalid_list:
            r = 'invalid_asn'
        elif 'invalid_maxlen' in invalid_list:
            r = 'invalid_maxlen'

    return r

def rovproc_single(roamap, pfx, length, asnset, pfxstr):
    r = 'unknown'
    pfx_exists = False
    invalid_list = []
    for pl in range(length, -1, -1):
        if pl not in roamap:
            continue
        t = pfx[:pl]
        if t in roamap[pl]:
            pfx_exists = True
            vrpset = roamap[pl][t]
            n = vrpset['num']
            vrps = vrpset['vrps']
            for i in range(n):
                v = vrps[i]
                maxlen = v['maxlen']
                asn = v['asn']
                if length <= maxlen and asn == asnset:
                    r = 'valid'
                elif asn != asnset:
                    invalid_list.append('invalid_asn')
                else:
                    invalid_list.append('invalid_maxlen')
    
    if pfx_exists and r!= 'valid':
        if 'invalid_asn' in invalid_list:
            r = 'invalid_asn'
        elif 'invalid_maxlen' in invalid_list:
            r = 'invalid_maxlen'

    return r

def rovproc2_single(roamap, pfx, length, asnset, pfxstr):
    r = 'unknown'
    pfx_exists = False
    invalid_list = []
    for pl in range(length, -1, -1):
        if pl not in roamap:
            continue
        t = pfx[:pl]
        if t in roamap[pl]:
            pfx_exists = True
            vrpset = roamap[pl][t]
            n = vrpset['num']
            vrps = vrpset['vrps']
            for i in range(n):
                v = vrps[i]
                maxlen = v['maxlen']
                asn = v['asn']
                if pl == length and asn == asnset:
                    invalid_list.append('valid')
                elif pl == length and asn != asnset:
                    invalid_list.append('invalid')
                elif pl < length and asn == asnset:
                    invalid_list.append('match')
                elif pl != length and asn != asnset:
                    invalid_list.append('notmatch')
                else :
                    invalid_list.append('unknown')
    
    if 'valid' in invalid_list:
        return 'valid'
    
    if 'invalid' in invalid_list:
        return 'invalid'
    
    if 'match' in invalid_list:
        return 'match'
    
    if 'notmatch' in invalid_list:
        return 'notmatch'


    return r


def rov_single(key, roamap_v4, roamap_v6, flag, data_nonvalid, data_cro):
    data_bgp = {}
    data_bgp[key] = 0
    pfxmap_v4 = {}
    pfxmap_v6 = {}
    try:
        getpfxmap(pfxmap_v4, pfxmap_v6, data_bgp)
    except:
        print('Error key ', key)
        return

    num = 0
    for pl in range(128, -1, -1):
        if pl not in pfxmap_v6:
            continue
        pfxs = pfxmap_v6[pl]
        for pfx in pfxs:
            asns_list = pfxs[pfx]['asns']
            pfxstr_list = pfxs[pfx]['prefix']
            for i in range(len(asns_list)):
                asns = asns_list[i]
                pfxstr = pfxstr_list[i]
                asn = int(asns)
                if flag == 'irr':
                    r_roa = rovproc2_single(roamap_v6, pfx, pl, asns, pfxstr)
                elif flag == 'cro':
                    r_roa = rovproc_cro_single(roamap_v6, pfx, pl, asns, pfxstr, data_nonvalid, data_cro)
                else:
                    r_roa = rovproc_single(roamap_v6, pfx, pl, asns, pfxstr)
                num += 1
    

    for pl in range(32, -1, -1):
        if pl not in pfxmap_v4:
            continue
        pfxs = pfxmap_v4[pl]
        for pfx in pfxs:
            asns_list = pfxs[pfx]['asns']
            pfxstr_list = pfxs[pfx]['prefix']
            for i in range(len(asns_list)):
                asns = asns_list[i]
                pfxstr = pfxstr_list[i]
                asn = int(asns)
                if flag == 'irr':
                    r_roa = rovproc2_single(roamap_v4, pfx, pl, asns, pfxstr)
                elif flag == 'cro':
                    r_roa = rovproc_cro_single(roamap_v4, pfx, pl, asns, pfxstr, data_nonvalid, data_cro)
                else:
                    r_roa = rovproc_single(roamap_v4, pfx, pl, asns, pfxstr)
                num += 1
    
    if num == 1:
        return r_roa
    
    else:
        print("error, ", num)
        return r_roa

def process_total_path(data_nonvalid, total_path_file):
    num = 0
    num_valid = 0
    num_invalid = 0
    num_unknown = 0
    f = open(total_path_file, 'r')
    for line in f:
        line_temp = line.split(' ')
        if '{' in line_temp[2]:
            num += 1
            continue
        date = line_temp[0]
        timestamp = line_temp[1]
        asn = int(line_temp[2])
        prefix = line_temp[3]
        result = line_temp[4]
        path = line.split('[')[1].split(']')[0]
        key = (prefix, asn)
        if key not in data_nonvalid:
            data_nonvalid[key] = {}
            data_nonvalid[key]['result'] = result
            data_nonvalid[key]['path'] = path
            data_nonvalid[key]['date'] = date
            data_nonvalid[key]['timestamp'] = timestamp
            data_nonvalid[key]['new_result'] = ''
            data_nonvalid[key]['new_reason'] = ''
            data_nonvalid[key]['detail'] = []
        else:
            print("error", key)
    
    keys_to_delete = []
    for key, item in data_nonvalid.items():
        with lock_cro:
            r_rov = rov_single(key, cromap_v4, cromap_v6, 'cro', data_nonvalid, data_cro)
        
        if r_rov == 'unknown':
            num_unknown += 1
            item['result'] = r_rov
        elif 'invalid' in r_rov:
            num_invalid += 1
            item['result'] = 'invalid'
        else:
            num_valid += 1
            keys_to_delete.append(key)
            record_file = 'record/' + date
            with lock_record:
                with open(record_file, 'a') as f:
                    f.write(line)
    
    for key in keys_to_delete:
        data_nonvalid.pop(key)
    
    
    num_total = num_valid + num_invalid + num_unknown
    
    f_record = open('/home/demo/route_analyze/cro_data/record_local', 'a')
    f_record.write("Now: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '\n')
    f_record.write("Initial result, Total: " + str(num_total) + " Valid: " + str(num_valid) + "(" + str(f"{(num_valid*100/num_total):.2f}") + "%)" 
     + " Invalid: " + str(num_invalid) + "(" + str(f"{(num_invalid*100/num_total):.2f}") + "%)" 
     + " Unknown: " + str(num_unknown) + "(" + str(f"{(num_unknown*100/num_total):.2f}") + "%)" + '\n')
    write_str = 'as-set route: ' + str(num)
    f_record.write(write_str + '\n')
    f_record.close()

    print(f"Update update!")

def checkASc2pBFS3(asn, root, ty_pe, asrel_cus):
    if len(root) > 0:
        if asn in root:
            return True
        for temp in root:
            if temp in asrel_cus:
                root1 = asrel_cus[temp][ty_pe]
            else:
                continue
            if len(root1) > 0:
                if asn in root1:
                    return True
                for temp1 in root1:
                    if temp1 in asrel_cus:
                        root2 = asrel_cus[temp][ty_pe]
                    else:
                        continue
                    if len(root2) > 0:
                        if asn in root2:
                            return True

    return False

def checkASc2p(as1, as2, asrel, asrel_cus):
    if (as1, as2) in asrel and asrel[(as1, as2)] == -1:
        return True
    elif (as2, as1) in asrel and asrel[(as2, as1)] == -1:
        return True
    
    #customer
    try:
        root = asrel_cus[as1]['customer']
        if checkASc2pBFS3(as2, root, 'customer', asrel_cus):
            return True
    except:
        pass
    
    #provider
    try:
        root = asrel_cus[as1]['provider']
        if checkASc2pBFS3(as2, root, 'provider', asrel_cus):
            return True
    except:
        pass
    
    return False

def get_notsure_score(key, item, roa_rov, f_invalid):
    
    #irr
    with lock_irr:
        irr_rov = rov_single(key, irrmap_v4, irrmap_v6, 'irr', {}, {})
    

    #bgp day
    with lock_bgp:
        if key in data_bgp_total:
            day = data_bgp_total[key]
        else:
            day = 0
        
    # reason
    roa_flag = 0
    for temp in item['detail']:
        if 'ROA' in temp[3]:
            roa_flag = 1
            break
    
    # AS
    with lock_as2org:
        #AS country
        try:
            country =  data_as_country[int(key[1])]
        except:
            country = 'None'
        
        #AS name
        try:
            org = as2org[int(key[1])]
        except:
            org = 'Unknown'

    
    #hijack
    with lock_bgp_current:
        prefix = key[0]
        pfx = prefix.split('/')[0]
        pfxlen = int(prefix.split('/')[1].split('\n')[0])
        asns = int(key[1])
        length = int(pfxlen)
        pfxbin = getpfxbin(pfx, length)
        hijack_flag = 0
        hijack_list = ''
        if ':' in key[0]:
            for pl in range(length, -1, -1):
                if pl not in data_bgp_currentmap_v6:
                    continue
                t = pfxbin[:pl]
                if t in data_bgp_currentmap_v6[pl]:
                    vrpset = data_bgp_currentmap_v6[pl][t]
                    for asn in vrpset['asns']:
                        if asn != asns:
                            hijack_list += '[' + vrpset['prefix'][0] + ' ' + str(asn) + '] '
                            hijack_flag = 1
                        elif asn == asns:
                            hijack_flag == 2
                            hijack_list = ''
                            break
                if hijack_flag != 0:
                    break         
        else:
            for pl in range(length, -1, -1):
                if pl not in data_bgp_currentmap_v4:
                    continue
                t = pfxbin[:pl]
                if t in data_bgp_currentmap_v4[pl]:
                    vrpset = data_bgp_currentmap_v4[pl][t]
                    for asn in vrpset['asns']:
                        if asn != asns:
                            hijack_list += '[' + vrpset['prefix'][0] + ' ' + str(asn) + '] '
                            hijack_flag = 1
                        elif asn == asns:
                            hijack_flag == 2
                            hijack_list = ''
                            break
                if hijack_flag != 0:
                    break  

        if hijack_list == '':
            hijack_list = 'None'   

    if roa_flag == 1:
        status = 'high   '
    elif irr_rov != 'valid' and hijack_flag == 1:
        status = 'high   '
    elif irr_rov == 'invalid' and 'invalid' in roa_rov:
        status = 'high   '
    elif 'invalid' in roa_rov and hijack_flag == 1:
        status = 'high   '
    else:
        status = 'medium '


    #write
    record_file = 'record/' + item['date']
    with lock_record:
        with open(record_file, 'a') as f:
            line = item['date'] + ' ' + item['timestamp']  + ' ' + str(key[1])  + ' ' + key[0]  + ' ' + item['result']  + ' [' + item['path'] + ']'
            f.write(line + '\n')
    record_file = 'record/' + item['date'] + '_' + item['result']  
    write_str = '{'
    for temp in item['detail']:
        write_str += '[' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '   
    write_str += '}'
    with lock_record:
        with open(record_file, 'a') as f:
            line = item['date'] + ' ' + item['timestamp']  + ' ' + status + ' ' + str(key[1])  + ' ' + key[0]  + ' ' + roa_rov  + ' ' + irr_rov  + ' ' + country + ' ' + org + ' ' + str(day) + ' ' + hijack_list + ' ' + write_str + ' [' + item['path'] + ']'
            f.write(line + '\n')
    
    if status == 'high   ':
        record_file = 'record/' + item['date'] + '_high' 
        write_str = '{'
        for temp in item['detail']:
            write_str += '[' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '   
        write_str += '}'
        with lock_record:
            with open(record_file, 'a') as f:
                line = item['date'] + ' ' + item['timestamp']  + ' ' + status + ' ' + str(key[1])  + ' ' + key[0]  + ' ' + item['result']    + ' ' + roa_rov  + ' ' + irr_rov  + ' ' + country + ' ' + org + ' ' + str(day) + ' ' + hijack_list + ' ' + write_str + ' [' + item['path'] + ']'
                f.write(line + '\n')
    
    #write
    write_str = key[0] + ', ' + str(key[1]) + ', ' + irr_rov + ', ' + str(day) + ', ' + country + ', invalid: '
    for temp in item['detail']:
        write_str += '[' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '
    f_invalid.write(date.today().strftime("%Y-%m-%d") + ', ' + write_str + '\n')

    return status

def retification(data_nonvalid):
    
    num_aggregate = 0
    num_length = 0
    num_asrel = 0
    num_sameas = 0
    num_roa = 0
    num_irr = 0
    num_score = 0
    num_path = 0
    num_high = 0
    f_invalid = open('/home/demo/route_analyze/cro_data/still_invalid_local', 'a')
    f_unknown = open('/home/demo/route_analyze/cro_data/still_unknown_local', 'a')
    f_new_valid = open('/home/demo/route_analyze/cro_data/new_valid_local', 'a')
    valid_list = {}
    

    for key, item in data_nonvalid.items():
        #step0 rov
        with lock_roa:
            roa_rov = rov_single(key, real_roamap_v4, real_roamap_v6, '', {}, {})
        if roa_rov == 'valid':
            item['new_result'] = 'valid'
            item['new_reason'] = 'roa'
            num_roa += 1
            valid_list[key] = 0
            record_file = 'record/' + item['date']
            with lock_record:
                with open(record_file, 'a') as f:
                    line = item['date'] + ' ' + item['timestamp']  + ' ' + str(key[1])  + ' ' + key[0]  + ' ' + item['new_result']  + ' [' + item['path']   + '] ' + item['new_reason']
                    f.write(line + '\n')
            
            record_file = 'record/' + item['date'] + '_' + item['result']     
            write_str = '{'
            for temp in item['detail']:
                write_str += '[' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '   
            write_str += '}'
            with lock_record:
                with open(record_file, 'a') as f:
                    line = item['date'] + ' ' + item['timestamp']  + ' ' + 'low    ' + ' ' + str(key[1])  + ' ' + key[0]  + ' ' + item['new_reason'] + ' ' + write_str  + ' [' + item['path'] + ']'
                    f.write(line + '\n')
            continue
            
        #step1 aggregate
        with lock_cro_aggregate:
            r_rov = rov_single(key, roamap_v4, roamap_v6, '', {}, {})
        if r_rov == 'valid':
            item['new_result'] = 'valid'
            item['new_reason'] = 'roa-aggregate'
            num_aggregate += 1
            valid_list[key] = 0
            record_file = 'record/' + item['date']
            with lock_record:
                with open(record_file, 'a') as f:
                    line = item['date'] + ' ' + item['timestamp']  + ' ' + str(key[1])  + ' ' + key[0]  + ' ' + item['new_result']  + ' [' + item['path']   + '] ' + item['new_reason']
                    f.write(line + '\n')
            record_file = 'record/' + item['date'] + '_' + item['result']
            write_str = '{'
            for temp in item['detail']:
                write_str += '[' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '   
            write_str += '}'
            with lock_record:
                with open(record_file, 'a') as f:
                    line = item['date'] + ' ' + item['timestamp']  + ' ' + 'low    ' + ' ' + str(key[1])  + ' ' + key[0]  + ' ' + item['new_reason'] + ' ' + write_str + ' [' + item['path'] + ']'
                    f.write(line + '\n')
            continue
            
        
        if item['result'] == 'unknown':
            write_str = key[0] + ', ' + str(key[1])
            f_unknown.write(date.today().strftime("%Y-%m-%d") + ', ' + write_str + '\n')
            record_file = 'record/' + item['date']
            with lock_record:
                with open(record_file, 'a') as f:
                    line = item['date'] + ' ' + item['timestamp']  + ' ' + str(key[1])  + ' ' + key[0]  + ' ' + item['result'] + ' [' + item['path'] + ']'
                    f.write(line + '\n')
            status = get_notsure_score(key, item, roa_rov, f_unknown)
            if 'high' in status:
                num_high += 1
            continue
        
        #step2 length
        maxlength_length = 0
        as_length = []
        for temp in item['detail']:
            if int(temp[2]) > maxlength_length:
                maxlength_length = int(temp[2])
                as_length = [int(temp[1])]
            elif int(temp[2]) == maxlength_length:
                maxlength_length = int(temp[2])
                as_length.append(int(temp[1]))
        if int(key[1]) in as_length:
            item['new_result'] = 'valid'
            item['new_reason'] = 'length'
            num_length += 1
            valid_list[key] = 0
            record_file = 'record/' + item['date']
            with lock_record:
                with open(record_file, 'a') as f:
                    line = item['date'] + ' ' + item['timestamp']  + ' ' + str(key[1])  + ' ' + key[0]  + ' ' + item['new_result']  + ' [' + item['path']   + '] ' + item['new_reason']
                    f.write(line + '\n')
            record_file = 'record/' + item['date'] + '_' + item['result']
            write_str = '{'
            for temp in item['detail']:
                write_str += '[' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '   
            write_str += '}'
            with lock_record:
                with open(record_file, 'a') as f:
                    line = item['date'] + ' ' + item['timestamp']  + ' ' + 'low    ' + ' ' + str(key[1])  + ' ' + key[0]  + ' ' + item['new_reason'] + ' ' + write_str + ' [' + item['path'] + ']'
                    f.write(line + '\n')
            continue
        

        #step3 as-relationship
        with lock_asrel:
            for temp in item['detail']:
                if checkASc2p(int(temp[1]), int(key[1]), asrel, asrel_cus):
                    item['new_result'] = 'valid'
                    item['new_reason'] = 'c2p'
                    break
        if item['new_result'] == 'valid':
            num_asrel += 1
            valid_list[key] = 0
            record_file = 'record/' + item['date']
            with lock_record:
                with open(record_file, 'a') as f:
                    line = item['date'] + ' ' + item['timestamp']  + ' ' + str(key[1])  + ' ' + key[0]  + ' ' + item['new_result']  + ' [' + item['path']   + '] ' + item['new_reason']
                    f.write(line + '\n')
            record_file = 'record/' + item['date'] + '_' + item['result']
            write_str = '{'
            for temp in item['detail']:
                write_str += '[' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '   
            write_str += '}'
            with lock_record:
                with open(record_file, 'a') as f:
                    line = item['date'] + ' ' + item['timestamp']  + ' ' + 'low    ' + ' ' + str(key[1])  + ' ' + key[0]  + ' ' + item['new_reason'] + ' ' + write_str + ' [' + item['path'] + ']'
                    f.write(line + '\n')
            continue
            
        
        #step4 same-as
        with lock_as2org:
            for temp in item['detail']:
                if int(temp[1]) in as2org and int(key[1]) in as2org and as2org[int(temp[1])] == as2org[int(key[1])]:
                    item['new_result'] = 'valid'
                    item['new_reason'] = 'org'
                    break
                if int(temp[1]) in similar_as and int(key[1]) in similar_as and similar_as[int(temp[1])] == similar_as[int(key[1])]:
                    item['new_result'] = 'valid'
                    item['new_reason'] = 'org'
                    break
        if item['new_result'] == 'valid':
            num_sameas += 1
            valid_list[key] = 0
            record_file = 'record/' + item['date']
            with lock_record:
                with open(record_file, 'a') as f:
                    line = item['date'] + ' ' + item['timestamp']  + ' ' + str(key[1])  + ' ' + key[0]  + ' ' + item['new_result']  + ' [' + item['path']   + '] ' + item['new_reason']
                    f.write(line + '\n')
            record_file = 'record/' + item['date'] + '_' + item['result']
            write_str = '{'
            for temp in item['detail']:
                write_str += '[' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '   
            write_str += '}'
            with lock_record:
                with open(record_file, 'a') as f:
                    line = item['date'] + ' ' + item['timestamp']  + ' ' + 'low    ' + ' ' + str(key[1])  + ' ' + key[0]  + ' ' + item['new_reason'] + ' ' + write_str + ' [' + item['path'] + ']'
                    f.write(line + '\n')
            continue
        
        #step5 ROA_AS in AS_PATH
        path_list = item['path'].split(' ')[:-1]
        for temp in item['detail']:
            if str(temp[1]) in path_list:
                item['new_result'] = 'valid'
                item['new_reason'] = 'path'
                break
        if item['new_result'] == 'valid':
            num_path += 1
            valid_list[key] = 0
            record_file = 'record/' + item['date']
            with lock_record:
                with open(record_file, 'a') as f:
                    line = item['date'] + ' ' + item['timestamp']  + ' ' + str(key[1])  + ' ' + key[0]  + ' ' + item['new_result']  + ' [' + item['path']   + '] ' + item['new_reason']
                    f.write(line + '\n')
            record_file = 'record/' + item['date'] + '_' + item['result']
            write_str = '{'
            for temp in item['detail']:
                write_str += '[' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '   
            write_str += '}'
            with lock_record:
                with open(record_file, 'a') as f:
                    line = item['date'] + ' ' + item['timestamp']  + ' ' + 'low    ' + ' ' + str(key[1])  + ' ' + key[0]  + ' ' + item['new_reason'] + ' ' + write_str + ' [' + item['path'] + ']'
                    f.write(line + '\n')
            continue

        #step-c check score
        status = get_notsure_score(key, item, roa_rov, f_invalid)
        if 'high' in status:
            num_high += 1
       
        

    f_unknown.close()
    f_invalid.close()
    with lock_route_add:
        f_valid = open('/home/demo/route_analyze/cro_data/valid_local', 'a')
        f_valid.write("Now: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '\n')
        for key in valid_list:
            write_str = key[0] + ', ' + str(key[1])
            f_valid.write(write_str + '\n')
        f_valid.close()

    for key, item in data_nonvalid.items():
        if item['new_result'] == 'valid':
            write_str = key[0] + ', ' + str(key[1]) + ', ' + item['result'] + ', ' + item['new_result'] + ', ' + item['new_reason'] + ', invalid: '
            for temp in item['detail']:
                write_str += '[' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '
            f_new_valid.write(date.today().strftime("%Y-%m-%d") + ', ' + write_str + '\n')
    f_new_valid.close()


    f_record = open('/home/demo/route_analyze/cro_data/record_local', 'a')
    write_str = 'total non-valid: ' + str(len(data_nonvalid)) + ' still invalid & unknown: ' + str(len(data_nonvalid) - (num_roa + num_aggregate + num_length + num_asrel + num_sameas + num_path + num_score))
    write_str = write_str + ' reason: ' + str(num_roa) + ' ' + str(num_aggregate) + ' ' + str(num_length) + ' ' + str(num_asrel) + ' ' + str(num_sameas) + ' ' + str(num_path) + ' ' + str(num_score)
    f_record.write(write_str + '\n')
    write_str = 'high level: ' + str(num_high)
    f_record.write(write_str + '\n')
    f_record.close()

    print(num_roa, num_aggregate, num_length, num_asrel, num_sameas, num_path, num_score, num_roa + num_aggregate + num_length + num_asrel + num_sameas + num_path + num_score)
    print("still invalid & unknown: " + str(len(data_nonvalid) - (num_roa + num_aggregate + num_length + num_asrel + num_sameas + num_path + num_score)))


def roa_write_cro(file, new_file):
    # start process
    f1 = open(file, 'r')
    f2 = open(new_file, 'w')

    # flag = 0: lines before "roas": [, flag = 1: lines after "roas": [
    flag = 0
    for line in f1:
        if "asn" not in line:
            if flag == 0:
                f2.write(line)
            continue
        if flag == 0:
            flag = 1
        if line[-2] != ',':
            f2.write(line[:-1] + ',\n')
        else:
            f2.write(line)
    f1.close()
    f2.close()

def read_rectification_cro(route_add_file, new_file):
    num = 0
    f1 = open(new_file, 'a')
    route_new = {}
    with lock_route_add:
        f2 = open(route_add_file, 'r')
        for line in f2:
            line_list = line.split(', ')
            try:
                prefix = str(line_list[0])
                asn = int(line_list[1].split('\n')[0])
                maxLength = int(prefix.split('/')[1])
                if (prefix, asn, maxLength) not in route_new:
                    route_new[(prefix, asn, maxLength)] = 0
                    f1.write("{ \"asn\": \"AS" + str(asn) + "\", \"prefix\": \"" + prefix + "\", \"maxLength\": " + str(maxLength) + ", \"source\": [ { \"type\": \"Route_correction\", \"uri\": \"\", \"tal\": \"\", \"validity\": { \"notBefore\": \"\", \"notAfter\": \"\" }, \"chainValidity\": { \"notBefore\": \"\", \"notAfter\": \"\" } }] },\n")
                    num += 1
            except:
                continue
        f2.close()
    f1.close()
    return num

def to_cro(add_num, new_file):
    with open(new_file, 'r') as file:
        lines = file.readlines()

    if lines:
        last_line = lines[-1].rstrip('\n,') 
        lines[-1] = last_line + '\n'

        num = int(lines[2].split(': ')[1].split(',')[0])
        lines[2] = '\"generated\": ' + str(num + add_num) + ',\n'

        with open(new_file, 'w') as file:
            file.writelines(lines)
            file.write("]}\n")
    

def write_new_cro(file, new_file, route_add_file):
    while True:
        time.sleep(21600) 
        try:
            roa_write_cro(file, new_file)
            add_num = read_rectification_cro(route_add_file, new_file)
            to_cro(add_num, new_file)
            
            with lock_cro:
                os.system(f'cp {new_file} {cro_file}')
            
            
            with lock_route_add:
                os.system(f'cp {route_add_file} /home/demo/route_analyze/cro_data/valid_local_old')
                f2 = open(route_add_file, 'w')
                f2.close()
            
        except FileNotFoundError:
            print(f"Update failed.")
        

def main():
    spemap_v4 = {}
    spemap_v6 = {}
    getspemap(spemap_v4, spemap_v6, private_ip_list_v4, private_ip_list_v6)

    thread1 = threading.Thread(target=read_CRO, args=(cro_file,))
    thread1_roa = threading.Thread(target=read_ROA, args=(roa_file,))
    thread2 = threading.Thread(target=read_roa_aggregate, args=(cro_aggregate_file,))
    thread3 = threading.Thread(target=process_irr, args=(irr4irr4_file_file, irr6_file, spemap_v4, spemap_v6,))
    thread4 = threading.Thread(target=process_bgp_total, args=(bgp_frequency_file,))
    thread5 = threading.Thread(target=process_asrel, args=(asrel_file,))
    thread6 = threading.Thread(target=process_as2org, args=(as2org_file,))
    thread7 = threading.Thread(target=write_new_cro, args=(cro_file, new_file, route_add_file,))
    thread8 = threading.Thread(target=process_bgp_current, args=(bgp_current_file, spemap_v4, spemap_v6,))
    thread1.start()
    thread1_roa.start()
    thread2.start()
    thread3.start()
    thread4.start()
    thread5.start()
    thread6.start()
    thread7.start()
    thread8.start()
    
    
    while True:
        try:
            global mod_time_non_valid
            current_mod_time = os.path.getmtime(non_valid_file)
            if current_mod_time != mod_time_non_valid:
                data_nonvalid = {}
                process_total_path(data_nonvalid, non_valid_file)
                mod_time_non_valid = current_mod_time
                retification(data_nonvalid)
        except:
            print(f"File {non_valid_file} not found.")
            pass
        time.sleep(5) 
    

if __name__ == "__main__":
    main()