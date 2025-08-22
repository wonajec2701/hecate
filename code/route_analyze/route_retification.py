from source_analysis import checkspepfx, checkspeasn, private_ip_list_v4, private_ip_list_v6
from source_analysis import getspemap, getroamap, getpfxmap, getpfxbin, process_irr, process_bgp_total, process_roa
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from math import pi
import numpy as np
import os
import re
import sys
import copy
#import addr
import json
import time
import netaddr
import ipaddress
import multiprocessing
current_directory = sys.argv[1]
content = sys.argv[2]
yesterday = sys.argv[3]
still_invalid = 0
still_unknown = 0
def read_CRO(file):
    f1 = open(file, 'r')
    print(file)
    data = {}
    data_asn = {}
    for line in f1:
        if "asn" not in line:
            continue
        asn = int(line.split("asn\": \"")[1].split("\"")[0][2:])
        prefix = line.split("prefix\": \"")[1].split("\"")[0]
        maxLength = int(line.split("maxLength\": ")[1].split(",")[0])
        ty_pe = line.split("type\": \"")[1].split("\"")[0]
        talist = line.split("tal\": \"")[1].split("\"")[0]

        if (prefix, asn, maxLength) not in data:
            data[(prefix, asn, maxLength)] = {}
            data[(prefix, asn, maxLength)]['source'] = ty_pe
            data[(prefix, asn, maxLength)]['valid'] = []
            data[(prefix, asn, maxLength)]['invalid'] = []
        
        if asn not in data_asn:
            data_asn[asn] = {}
            data_asn[asn][maxLength] = [prefix]
        else:
            if maxLength not in data_asn[asn]:
                data_asn[asn][maxLength] = [prefix]
            else:
                data_asn[asn][maxLength].append(prefix)

    f1.close()
    return data, data_asn


def rovproc_single(roamap, pfx, length, asnset, pfxstr):
    r = 'unknown'
    pfx_exists = False
    invalid_list = []
    for pl in range(length, -1, -1):
        if pl not in roamap:
            continue
        t = pfx[:pl]
        if t in roamap[pl]:
            #print(pl, t)
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

def rov_single(key, roamap_v4, roamap_v6, flag=''):
    data_bgp = {}
    data_bgp[key] = 0
    pfxmap_v4 = {}
    pfxmap_v6 = {}
    getpfxmap(pfxmap_v4, pfxmap_v6, data_bgp)

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
                else:
                    r_roa = rovproc_single(roamap_v4, pfx, pl, asns, pfxstr)
                num += 1
    
    if num == 1:
        return r_roa
    
    else:
        print("error, ", num)
        return r_roa
                

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

def process_as_org(caida_file, data_as_country):
    
    as2org = {}
    org2country = {}
    process_as_country(caida_file, as2org, org2country)
    for asn in as2org:
        data_as_country[asn] = org2country[as2org[asn]]
    
    return as2org


def process_asrel(f, asrel, asrel_cus):
    f1 = open(f, 'r', encoding = "ISO-8859-1")
    for line in f1:
        if '#' in line:
            continue
        temp = line.split('|')
        asrel[(int(temp[0]), int(temp[1]))] = int(temp[2].split('\n')[0])
        if int(temp[2].split('\n')[0]) != -1:
            continue
        if int(temp[0]) not in asrel_cus:
            asrel_cus[int(temp[0])] = {}
            asrel_cus[int(temp[0])]['customer'] = [int(temp[1])]
            asrel_cus[int(temp[0])]['provider'] = []
        else:
            asrel_cus[int(temp[0])]['customer'].append(int(temp[1]))
        
        if int(temp[1]) not in asrel_cus:
            asrel_cus[int(temp[1])] = {}
            asrel_cus[int(temp[1])]['customer'] = []
            asrel_cus[int(temp[1])]['provider'] = [int(temp[0])]
        else:
            asrel_cus[int(temp[1])]['provider'].append(int(temp[0]))


def could_reach(prefix, prefix_list):
    if prefix in prefix_list:
        print("error, could_reach")
    subprefix = []
    supernet_network = ipaddress.ip_network(prefix)
    for temp in prefix_list:
        subnet_network = ipaddress.ip_network(temp)
        if subnet_network.version == supernet_network.version and supernet_network.subnet_of(subnet_network):
            return 1  #reachable
        if subnet_network.version == supernet_network.version and subnet_network.subnet_of(supernet_network):
            subprefix.append(temp)
    new_networks = netaddr.cidr_merge(subprefix)
    if len(subprefix) == 0:
        return 0 #unreachable
    for temp in new_networks:
        if temp == prefix:
            return 1
    
    return 2 #partially reachable

def read_roa_aggregate(filename, data_aggregate):
    f2 = open(filename, 'r')
    for line in f2:
        line_list = line.split(' ')
        try:
            prefix = str(line_list[1])
            asn = int(line_list[0])
            maxLength = int(line_list[2])
            if (prefix, asn, maxLength) not in data_aggregate:
                data_aggregate[(prefix, asn, maxLength)] = {}
                data_aggregate[(prefix, asn, maxLength)]['type'] = ['roa_aggregate']
        except:
            continue
    f2.close()

def roa_aggregate_split(lock, data_asn, data, data_aggregate):
    for key in data_asn:
        for maxlen in data_asn[key]:
            networks = []
            temp_list = copy.deepcopy(data_asn[key][maxlen])
            for prefix in data_asn[key][maxlen]:
                networks.append(prefix)
            new_networks = netaddr.cidr_merge(networks)
            for temp in new_networks:
                temp_list_1 = copy.deepcopy(temp_list)
                prefix = str(temp)
                asn = int(key)
                maxLength = int(maxlen)
                initial_prefixs = []
                for initial_prefix in temp_list:
                    if ipaddress.ip_address(initial_prefix.split('/')[0]) in ipaddress.ip_network(temp):
                        initial_prefixs.append((initial_prefix, asn, maxLength))
                        temp_list_1.remove(initial_prefix)
                temp_list = copy.deepcopy(temp_list_1)
                if len(initial_prefixs) > 1:
                    lock.acquire()
                    try:
                        if (prefix, asn, maxLength) not in data and (prefix, asn, maxLength) not in data_aggregate:
                            data_aggregate[(prefix, asn, maxLength)] = {}
                            data_aggregate[(prefix, asn, maxLength)]['type'] = ['roa_aggregate']
                    finally:
                        lock.release()

                        

def roa_aggregate(data_asn, data):
    
    read_filename = yesterday + "/source_data/roa_aggregate_" + yesterday
    print(read_filename)
    creation_date_str = yesterday
    filename = yesterday + "/source_data/roa_aggregate_" + yesterday 
    data_aggregate = {}
    
    if os.path.exists(read_filename):
        print("read")
        read_roa_aggregate(read_filename, data_aggregate)
        if yesterday != creation_date_str:
            os.system(f'cp {read_filename} {filename}')
        return data_aggregate
    
    print("first time, write")

    #process aggregate
    
    process_num = 20
    manager = multiprocessing.Manager()
    data_aggregate = manager.dict()
    lock = manager.Lock()
    
    keys = list(data_asn.keys())
    keys_per_group = len(keys) // process_num
    ts = []
    for i in range(process_num):
        start = i * keys_per_group
        end = (i + 1) * keys_per_group
        group_keys = keys[start:end]
        group_dict = {key: data_asn[key] for key in group_keys}
        t = multiprocessing.Process(target=roa_aggregate_split, args=(lock, group_dict, data, data_aggregate))
        ts.append(t)
        t.start()
    for i in ts:
        i.join()

    
    f = open(filename, 'w')
    for key in data_aggregate:
        f.write(str(key[1]) + ' ' + key[0] + ' ' + str(key[2]) + '\n')
    f.close()
    
    if yesterday != creation_date_str:
        os.system(f'cp {read_filename} {filename}')
    if content == 'local':
        os.system(f'cp {read_filename} /home/demo/route_analyze/cro_data/cro_aggregate')
    
    return data_aggregate

def get_notsure_score(key, irrmap_v4, irrmap_v6, data_bgp_total, bgp_day_max, reachable_v_u, data_as_country, as2org, flag, f_valid_invalid, f_valid_unknown, f_invalid, f_unknown, item, roa_rov, anomaly_route):
    score = 0
    #irr
    r_rov = rov_single(key, irrmap_v4, irrmap_v6, 'irr')
    
    if r_rov == 'valid':
        score += 100

    #bgp day
    if key in data_bgp_total:
        day = data_bgp_total[key]
    else:
        day = 0
    
    if day > bgp_day_max * 0.8:
        score += 97
        
    #reachable
    if flag == 'invalid':
        try:
            reachable = could_reach(key[0], reachable_v_u[int(key[1])])
        except:
            reachable = 0
        if reachable == 0 or reachable == 2:
            score += 41

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
            score += 41
            just_maxlength = 1
        else:
            just_maxlength = 0
        

    #country
    try:
        country =  data_as_country[int(key[1])]
    except:
        country = 'None'
    
    try:
        org = as2org[int(key[1])]
    except:
        org = 'Unknown'
    

    
    if score >= 138:
        status = 'yes, '
    else:
        status = ''
    
    if key in anomaly_route:
        anomaly = 'Anomaly'
    else:
        anomaly = ' '

    #write
    if flag == 'invalid':
        write_str = status + anomaly + ', ' + key[0] + ', ' + str(key[1]) + ', ' + r_rov + ', ' + str(day) + ', ' + str(just_maxlength)  + ', ' + str(reachable) + ', ' + country  + ', '  + org  + ', ' + str(score) + ', invalid: '
        for temp in item['detail']:
            write_str += '[' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '
        f_invalid.write(write_str + '\n') 
        if status != 'yes, ':
            global still_invalid
            still_invalid += 1
        else:
            if 'invalid' in roa_rov:
                f_valid_invalid.write('{\"BGP Route Prefix\": \"' + key[0] + '\", \"ASN\": \"AS' + str(key[1]) + '\", \"Result\": \"' + roa_rov + '\", \"Source\": \"' + 'DCS' + '\"},\n')
            elif 'unknown' in roa_rov:
                f_valid_unknown.write('{\"BGP Route Prefix\": \"' + key[0] + '\", \"ASN\": \"AS' + str(key[1]) + '\", \"Result\": \"' + roa_rov + '\", \"Source\": \"' + 'DCS' + '\"},\n')
    
    elif flag == 'unknown':
        write_str = status + key[0] + ', ' + str(key[1]) + ', ' + r_rov + ', ' + str(day) + ', ' + country  + ', '  + org + ', ' + str(score)
        f_unknown.write(write_str + '\n')
        if score < 138:
            global still_unknown
            still_unknown += 1
        else:
            if 'invalid' in roa_rov:
                f_valid_invalid.write('{\"BGP Route Prefix\": \"' + key[0] + '\", \"ASN\": \"AS' + str(key[1]) + '\", \"Result\": \"' + roa_rov + '\", \"Source\": \"' + 'DCS' + '\"},\n')
            elif 'unknown' in roa_rov:
                f_valid_unknown.write('{\"BGP Route Prefix\": \"' + key[0] + '\", \"ASN\": \"AS' + str(key[1]) + '\", \"Result\": \"' + roa_rov + '\", \"Source\": \"' + 'DCS' + '\"},\n')
    
    return status

def read_invalid_unknown(invalid, unknown, valid, reachable_v_u):
    f = open(current_directory + '/cro_data/invalid_' + content, 'r')
    for line in f:
        prefix = line.split(' ')[0]
        asn = int(line.split(' ')[1])
        invalid_list = line.split('invalid: ')[1].split('\n')[0]
        regex = r'\[([^]]+)\]'  
        matches = re.findall(regex, invalid_list)
        invalid_reason = []
        for m in matches:
            m_list = m.split(',')
            invalid_reason.append([m_list[0], int(m_list[1]), int(m_list[2]), m_list[3]])
        if (prefix, asn) not in invalid:
            invalid[(prefix, asn)] = invalid_reason
    f.close()

    f = open(current_directory + '/cro_data/valid_' + content, 'r')
    for line in f:
        prefix = line.split(' ')[0]
        asn = int(line.split(' ')[1])
        valid_list = line.split('valid: ')[1].split('\n')[0]
        regex = r'\[([^]]+)\]'  
        matches = re.findall(regex, valid_list)
        valid_reason = []
        for m in matches:
            m_list = m.split(',')
            valid_reason.append([m_list[0], int(m_list[1]), int(m_list[2]), m_list[3]])
        if (prefix, asn) not in valid:
            valid[(prefix, asn)] = valid_reason

        if asn not in reachable_v_u:
            reachable_v_u[asn] = [prefix]
        elif prefix not in reachable_v_u[asn]:
            reachable_v_u[asn].append(prefix)
    f.close()

    f = open(current_directory + '/cro_data/unknown_' + content, 'r')
    for line in f:
        prefix = line.split(' ')[0]
        asn = int(line.split(' ')[1])
        if (prefix, asn) not in unknown:
            unknown[(prefix, asn)] = {}
        if asn not in reachable_v_u:
            reachable_v_u[asn] = [prefix]
        elif prefix not in reachable_v_u[asn]:
            reachable_v_u[asn].append(prefix)
    f.close()

    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        log.write(f"{content} total route: {len(valid) + len(invalid) + len(unknown)}, valid: {len(valid)}({len(valid) * 100 / (len(valid) + len(invalid) + len(unknown)):.2f}%), invalid: {len(invalid)}({len(invalid) * 100 / (len(valid) + len(invalid) + len(unknown)):.2f}%), unknown: {len(unknown)}({len(unknown) * 100 / (len(valid) + len(invalid) + len(unknown)):.2f}%).\n")


def process_anomaly_route(file, anomaly_route):
    if not os.path.exists(file):
        return
    with open(file, 'r') as f:
        for line in f:
            prefix = line.split(', ')[0]
            asn = int(line.split(', ')[1])
            if (prefix, asn) not in anomaly_route:
                anomaly_route[(prefix, asn)] = 0


def retification(data_cro, data_cro_asn, invalid, unknown, reachable_v_u):
    #step0 
    invalid_unknown = {}

    for key, item in invalid.items():
        if key not in invalid_unknown:
            invalid_unknown[key] = {}
            invalid_unknown[key]['result'] = 'invalid'
            invalid_unknown[key]['new_result'] = ''
            invalid_unknown[key]['new_reason'] = ''
            invalid_unknown[key]['detail'] = item
        else:
            print("error", key)
    
    for key in unknown:
        if key not in invalid_unknown:
            invalid_unknown[key] = {}
            invalid_unknown[key]['result'] = 'unknown'
            invalid_unknown[key]['new_result'] = ''
            invalid_unknown[key]['new_reason'] = ''
            invalid_unknown[key]['detail'] = []
        else:
            print("error", key)
    print("Total invalid and unknown : " + str(len(invalid_unknown)))

    #step1 aggregate
    data_aggregate = roa_aggregate(data_cro_asn, data_cro)
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        total_num = len(data_aggregate)
        log.write(f"{finish_timestamp} cro aggregate ended, added {total_num} aggregated records.\n")
    
    cromap_v4 = {}
    cromap_v6 = {}
    getroamap(cromap_v4, cromap_v6, data_aggregate)


    #step-c irr
    spemap_v4 = {}
    spemap_v6 = {}
    getspemap(spemap_v4, spemap_v6, private_ip_list_v4, private_ip_list_v6)

    data_irr_all = {}
    process_irr('/home/demo/multi_source_data/'+yesterday+'/irr_data/irr-route-total-'+yesterday, data_irr_all, spemap_v4, spemap_v6)
    process_irr('/home/demo/multi_source_data/'+yesterday+'/irr_data/irr-route6-total-'+yesterday, data_irr_all, spemap_v4, spemap_v6)
    irrmap_v4 = {}
    irrmap_v6 = {}
    getroamap(irrmap_v4, irrmap_v6, data_irr_all)

    #step-c roa

    data_roa = {}
    process_roa('/home/demo/multi_source_data/'+yesterday+'/roa_data/'+yesterday+'-0000', data_roa, spemap_v4, spemap_v6)
    roamap_v4 = {}
    roamap_v6 = {}
    getroamap(roamap_v4, roamap_v6, data_roa)
    

    #step-c bgp_frequency
    data_bgp_total = {}
    bgp_day_max = process_bgp_total('/home/demo/multi_source_data/' + yesterday+'/bgp_filter_data/bgp_frequency', data_bgp_total)
    
    #step-c anomaly
    anomaly_route = {}
    if content == 'rib':
        process_anomaly_route(yesterday + '/cro_data/anomaly_invalid_rib', anomaly_route)


    #step2 as
    asrel = {}
    asrel_cus = {}
    process_asrel('/home/demo/multi_source_data/CAIDA/relationship/as-rel2.txt', asrel, asrel_cus)

    data_as_country = {}
    as2org = process_as_org('/home/demo/multi_source_data/CAIDA/as_org/as-org2info.jsonl', data_as_country)

    
    num_roa = 0
    num_aggregate = 0
    num_length = 0
    num_asrel = 0
    num_sameas = 0
    num_irr = 0
    f_valid_invalid = open(current_directory + '/cro_data/roa_invalid_cro_valid_' + content, 'w')
    f_valid_invalid.write('{\"routes\": [')
    f_valid_unknown = open(current_directory + '/cro_data/roa_unknown_cro_valid_' + content, 'w')
    f_valid_unknown.write('{\"routes\": [')
    f_invalid = open(current_directory + '/cro_data/still_invalid_' + content, 'w')
    f_unknown = open(current_directory + '/cro_data/still_unknown_' + content, 'w')
    
    write_str = 'status'  + ', ' + 'Anomaly' + ', '  + 'prefix' + ', ' + 'ASN' + ', ' + 'irr_result' + ', ' + 'day_in_bgp_table' + ', ' + 'just_maxlength'  + ', ' + 'reachable' + ', ' + 'Country' + ', ' + 'score'  + ', invalid_reason'
    f_invalid.write(write_str + '\n')

    write_str = 'prefix' + ', ' + 'ASN'
    f_unknown.write(write_str + '\n')

    num_yes = 0
    num_invalid = 0

    for key, item in invalid_unknown.items():

        #step0 roa
        roa_rov = rov_single(key, roamap_v4, roamap_v6)
        if roa_rov == 'valid':
            invalid_unknown[key]['new_result'] = 'valid'
            invalid_unknown[key]['new_reason'] = 'roa-valid'
            num_roa += 1
            if int(key[1]) not in reachable_v_u:
                reachable_v_u[int(key[1])] = [key[0]]
            elif key[0] not in reachable_v_u[int(key[1])]:
                reachable_v_u[int(key[1])].append(key[0])
            #f_valid.write('{\"BGP Route Prefix\": \"' + key[0] + '\", \"ASN\": \"AS' + str(key[1]) + '\", \"Result\": \"' + roa_rov + '\", \"Source\": \"' + 'DCS' + '\"},\n')
            continue
        
        if 'invalid' in roa_rov:
            if int(key[1]) in reachable_v_u and key[0] in reachable_v_u[int(key[1])]:
                reachable_v_u[int(key[1])].remove(key[0])


        #step1 aggregate
        
        r_rov = rov_single(key, cromap_v4, cromap_v6)
        if r_rov == 'valid':
            invalid_unknown[key]['new_result'] = 'valid'
            invalid_unknown[key]['new_reason'] = 'roa-aggregate'
            num_aggregate += 1
            if 'invalid' in roa_rov:
                f_valid_invalid.write('{\"BGP Route Prefix\": \"' + key[0] + '\", \"ASN\": \"AS' + str(key[1]) + '\", \"Result\": \"' + roa_rov + '\", \"Source\": \"' + 'DCS' + '\"},\n')
            if 'unknown' in roa_rov:
                f_valid_unknown.write('{\"BGP Route Prefix\": \"' + key[0] + '\", \"ASN\": \"AS' + str(key[1]) + '\", \"Result\": \"' + roa_rov + '\", \"Source\": \"' + 'DCS' + '\"},\n')
            
            if int(key[1]) not in reachable_v_u:
                reachable_v_u[int(key[1])] = [key[0]]
            elif key[0] not in reachable_v_u[int(key[1])]:
                reachable_v_u[int(key[1])].append(key[0])
            continue
        
        if item['result'] == 'unknown':
            status = get_notsure_score(key, irrmap_v4, irrmap_v6, data_bgp_total, bgp_day_max, reachable_v_u, data_as_country, as2org, 'unknown', f_valid_invalid, f_valid_unknown, f_invalid, f_unknown, item, roa_rov, anomaly_route)
            continue
        
        if 'invalid' in r_rov:
            if int(key[1]) in reachable_v_u and key[0] in reachable_v_u[int(key[1])]:
                reachable_v_u[int(key[1])].remove(key[0])


        #step3 as-relationship
        
        for temp in item['detail']:
            if checkASc2p(int(temp[1]), int(key[1]), asrel, asrel_cus):
                item['new_result'] = 'valid'
                item['new_reason'] = 'c2p'
                break
        if item['new_result'] == 'valid':
            num_asrel += 1
            if 'invalid' in roa_rov:
                f_valid_invalid.write('{\"BGP Route Prefix\": \"' + key[0] + '\", \"ASN\": \"AS' + str(key[1]) + '\", \"Result\": \"' + roa_rov + '\", \"Source\": \"' + 'DCS' + '\"},\n')
            elif 'unknown' in roa_rov:
                f_valid_unknown.write('{\"BGP Route Prefix\": \"' + key[0] + '\", \"ASN\": \"AS' + str(key[1]) + '\", \"Result\": \"' + roa_rov + '\", \"Source\": \"' + 'DCS' + '\"},\n')
            
            if int(key[1]) not in reachable_v_u:
                reachable_v_u[int(key[1])] = [key[0]]
            elif key[0] not in reachable_v_u[int(key[1])]:
                reachable_v_u[int(key[1])].append(key[0])
            continue
        
        #step4 same-as
        
        for temp in item['detail']:
            if int(temp[1]) in as2org and int(key[1]) in as2org and as2org[int(temp[1])] == as2org[int(key[1])]:
                item['new_result'] = 'valid'
                item['new_reason'] = 'org'
                break
        if item['new_result'] == 'valid':
            num_sameas += 1
            if 'invalid' in roa_rov:
                f_valid_invalid.write('{\"BGP Route Prefix\": \"' + key[0] + '\", \"ASN\": \"AS' + str(key[1]) + '\", \"Result\": \"' + roa_rov + '\", \"Source\": \"' + 'DCS' + '\"},\n')
            elif 'unknown' in roa_rov:
                f_valid_unknown.write('{\"BGP Route Prefix\": \"' + key[0] + '\", \"ASN\": \"AS' + str(key[1]) + '\", \"Result\": \"' + roa_rov + '\", \"Source\": \"' + 'DCS' + '\"},\n')
            
            if int(key[1]) not in reachable_v_u:
                reachable_v_u[int(key[1])] = [key[0]]
            elif key[0] not in reachable_v_u[int(key[1])]:
                reachable_v_u[int(key[1])].append(key[0])
            continue

        #step-c check reason
        num_invalid += 1
        status = get_notsure_score(key, irrmap_v4, irrmap_v6, data_bgp_total, bgp_day_max, reachable_v_u, data_as_country, as2org, 'invalid', f_valid_invalid, f_valid_unknown, f_invalid, f_unknown, item, roa_rov, anomaly_route)
        if 'yes' in status:
            num_yes += 1
    
    f_valid_invalid.close()
    f_valid_unknown.close()
    with open(current_directory + '/cro_data/roa_invalid_cro_valid_' + content, 'r') as file:
        lines = file.readlines()
    if lines:
        last_line = lines[-1].rstrip('\n,')
        lines[-1] = last_line + '\n'


        with open(current_directory + '/cro_data/roa_invalid_cro_valid_' + content, 'w') as file:
            file.writelines(lines)
            file.write("]}\n")

    with open(current_directory + '/cro_data/roa_unknown_cro_valid_' + content, 'r') as file:
        lines = file.readlines()
    if lines:
        last_line = lines[-1].rstrip('\n,')
        lines[-1] = last_line + '\n'

        with open(current_directory + '/cro_data/roa_unknown_cro_valid_' + content, 'w') as file:
            file.writelines(lines)
            file.write("]}\n")
    
    f_unknown.close()
    f_invalid.close()
    print(num_roa, num_aggregate, num_length, num_asrel, num_sameas, num_irr, num_roa + num_aggregate + num_length + num_asrel + num_sameas + num_irr)
    print("still invalid & unknown: " + str(len(invalid_unknown) - (num_roa + num_aggregate + num_length + num_asrel + num_sameas + num_irr)))
    print("invalid: " + str(num_invalid) + " status_yes: " + str(num_yes))
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        total_num = len(data_aggregate)
        log.write(f"{finish_timestamp} route retification, total invalid & unknwon records: {len(invalid_unknown)}\n")
        log.write(f"roa-valid: {num_roa}, aggregate: {num_aggregate}, length: {num_length}, asrel: {num_asrel}, sameas: {num_sameas}, total: {num_roa + num_aggregate + num_length + num_asrel + num_sameas}\n")
        log.write(f"{content}, still invalid: {still_invalid}, still unknown: {still_unknown}, retification rate: {(len(invalid_unknown) - still_invalid - still_unknown) * 100 / len(invalid_unknown):.2f}%.\n")
        

def main():
    cro_file = "/home/demo/multi_source_data/" + yesterday + "/cro_data/cro_mdis_initial_" + yesterday

    start_time = datetime.now()
    start_timetamp = start_time.strftime("%Y%m%d %H:%M:%S")
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        log.write(f"{start_timetamp} route retification started\n")


    data_cro, data_cro_asn = read_CRO(cro_file)

    invalid = {}
    unknown = {}
    valid = {}
    reachable_v_u = {}
    read_invalid_unknown(invalid, unknown, valid, reachable_v_u)
    
    retification(data_cro, data_cro_asn, invalid, unknown, reachable_v_u)

    
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        duration = finish_time - start_time
        log.write(f"{finish_timestamp} route retification ended\n")
    

if __name__ == "__main__":
    main()