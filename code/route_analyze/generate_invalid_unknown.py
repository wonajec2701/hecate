from source_analysis import checkspepfx, checkspeasn, private_ip_list_v4, private_ip_list_v6
from source_analysis import getspemap, getroamap, getpfxmap, getpfxbin
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
import netaddr
import ipaddress
import multiprocessing
current_directory = sys.argv[1]
content = sys.argv[2]
yesterday = sys.argv[3]

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

def rovproc(roamap, pfx, length, asnset, pfxstr, data_bgp, data_roa, flag):
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
                if asnset == -1:
                    r = 'invalid'
                    invalid_list.append('invalid_asn')
                    data_bgp[(pfxstr, asnset)]['invalid'].append([v['vrp'], asn, maxlen, data_roa[(v['vrp'], asn, maxlen)]['source']])
                elif length <= maxlen and asn == asnset:
                    r = 'valid'
                    data_bgp[(pfxstr, asn)]['valid'].append([v['vrp'], asn, maxlen, data_roa[(v['vrp'], asn, maxlen)]['source']])
                    data_roa[(v['vrp'], asn, maxlen)]['valid'].append([pfxstr, asn])
                elif asn != asnset:
                    data_bgp[(pfxstr, asnset)]['invalid'].append([v['vrp'], asn, maxlen, data_roa[(v['vrp'], asn, maxlen)]['source']])
                    data_roa[(v['vrp'], asn, maxlen)]['invalid'].append([pfxstr, asnset])
                    invalid_list.append('invalid_asn')
                else:
                    data_bgp[(pfxstr, asnset)]['invalid'].append([v['vrp'], asn, maxlen, data_roa[(v['vrp'], asn, maxlen)]['source']])
                    data_roa[(v['vrp'], asn, maxlen)]['invalid'].append([pfxstr, asnset])
                    invalid_list.append('invalid_maxlen')
    
    if pfx_exists and r!= 'valid':
        if 'invalid_asn' in invalid_list:
            r = 'invalid_asn'
        elif 'invalid_maxlen' in invalid_list:
            r = 'invalid_maxlen'
    


    data_bgp[(pfxstr, asnset)]['result'] = r
    f = open(current_directory + '/cro_data/Router_Error_' + flag, 'a')
    router_r = data_bgp[(pfxstr, asnset)]['router-result']
    if (router_r == 'valid' or router_r == 'unknown') and router_r != r:
        if asnset == -1:
            write_str = pfxstr + ' ' + str(asnset) + ' ' + str(data_bgp[(pfxstr, asnset)]['as-set-asn']) + ' router: ' + router_r + ' server: ' + r
        else:
            write_str = pfxstr + ' ' + str(asnset) + ' router: ' + router_r + ' server: ' + r
        if r == 'valid':
            for temp in data_bgp[(pfxstr, asnset)]['valid']:
                write_str += ' [' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '
        elif 'invalid' in r:
            for temp in data_bgp[(pfxstr, asnset)]['invalid']:
                write_str += ' [' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '
        f.write(write_str + '\n')
        f.close()
    if router_r == 'invalid' and 'invalid' not in r:
        if asnset == -1:
            write_str = pfxstr + ' ' + str(asnset) + ' ' + str(data_bgp[(pfxstr, asnset)]['as-set-asn']) + ' router: ' + router_r + ' server: ' + r
        else:
            write_str = pfxstr + ' ' + str(asnset) + ' router: ' + router_r + ' server: ' + r
        if r == 'valid':
            for temp in data_bgp[(pfxstr, asnset)]['valid']:
                write_str += ' [' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '
        elif 'invalid' in r:
            for temp in data_bgp[(pfxstr, asnset)]['invalid']:
                write_str += ' [' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '
        f.write(write_str + '\n')
        f.close()
    return r


def rov(data_bgp, data_roa, spemap_v4, spemap_v6, flag):
    results = ['valid', 'invalid_asn', 'invalid_maxlen', 'unknown']
    results_v4 = [0,0,0,0]
    results_v6 = [0,0,0,0]
    valid = {}
    invalid = {}
    unknown = {}
    results_t = {}

    roamap_v4 = {}
    roamap_v6 = {}
    pfxmap_v4 = {}
    pfxmap_v6 = {}
    getroamap(roamap_v4, roamap_v6, data_roa)
    getpfxmap(pfxmap_v4, pfxmap_v6, data_bgp)
    f = open(current_directory + '/cro_data/Router_Error_' + flag, 'w')
    f.close()

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
                r_roa = rovproc(roamap_v6, pfx, pl, asns, pfxstr, data_bgp, data_roa, flag)
                results_v6[results.index(r_roa)] += 1
                if 'invalid' in r_roa:
                    invalid[(pfxstr, asn)] = data_bgp[(pfxstr, asn)]['invalid']
                if 'unknown' in r_roa:
                    unknown[(pfxstr, asn)] = {}
                if r_roa == 'valid':
                    valid[(pfxstr, asn)] = data_bgp[(pfxstr, asn)]['valid']
                results_t[(pfxstr, asn)] = r_roa
    

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
                r_roa = rovproc(roamap_v4, pfx, pl, asns, pfxstr, data_bgp, data_roa, flag)
                results_v4[results.index(r_roa)] += 1
                if 'invalid' in r_roa:
                    invalid[(pfxstr, asn)] = data_bgp[(pfxstr, asn)]['invalid']
                if 'unknown' in r_roa:
                    unknown[(pfxstr, asn)] = {}
                if r_roa == 'valid':
                    valid[(pfxstr, asn)] = data_bgp[(pfxstr, asn)]['valid']
                results_t[(pfxstr, asn)] = r_roa
    
    return results_v4, results_v6, invalid, unknown, valid


def process_bgp_local(file, data, spemap_v4, spemap_v6):
    f = open(file, 'r')
    num = 0
    for line in f:
        asn = line.split(' ')[0]
        if '{' in asn:
            asn = -1
            prefix = line.split(' ')[1]
            result = line.split(' ')[2]
            asn_n = line.split(' ')[3].split('\n')[0]
        else:
            asn = int(asn)
            prefix = line.split(' ')[1]
            result = line.split(' ')[2].split('\n')[0]
            asn_n = -1
        if result == 'not-found':
            result = 'unknown'
        pfx = prefix.split('/')[0]
        try:
            pl = int(prefix.split('/')[1].split('\n')[0])
        except:
            num += 1
            continue
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
        if (prefix, asn) not in data:
            data[(prefix, asn)] = {}
            data[(prefix, asn)]['num'] = 1
            data[(prefix, asn)]['router-result'] = result
            data[(prefix, asn)]['result'] = result
            data[(prefix, asn)]['valid'] = []
            data[(prefix, asn)]['invalid'] = []
            data[(prefix, asn)]['as-set-asn'] = asn_n
    print(num)
    
def process_bgp(file, data, spemap_v4, spemap_v6):
    with open(file, 'r') as file:
        json_data = json.load(file)

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
        if (prefix, asn) not in data:
            data[(prefix, asn)] = {}
            data[(prefix, asn)]['num'] = 1
            data[(prefix, asn)]['router-result'] = ''
            data[(prefix, asn)]['result'] = ''
            data[(prefix, asn)]['valid'] = []
            data[(prefix, asn)]['invalid'] = []

            

def analyze_validate(data_roa, data_bgp, spemap_v4, spemap_v6, data_cro_total, record_flag, flag=''):

    results_v4, results_v6, invalid, unknown, valid = rov(data_bgp, data_roa, spemap_v4, spemap_v6, flag)
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        log.write(f"cro-ipv4: {results_v4[0]}, {results_v4[1]}, {results_v4[2]}, {results_v4[3]}\n")
        log.write(f"cro-ipv6: {results_v6[0]}, {results_v6[1]}, {results_v6[2]}, {results_v6[3]}\n")
    print("cro: ", results_v4, results_v6)

    if record_flag:
        update_CRO_total(data_roa, data_cro_total, data_bgp)


    num = 0

    f = open(current_directory + '/cro_data/invalid_' + flag, 'w')
    for key, item in invalid.items():
        if key[1] == -1:
            num += 1
            continue
        write_str = key[0] + ' ' + str(key[1]) + ' invalid: '
        for temp in item:
            write_str += '[' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '
        f.write(write_str + '\n')
    f.close()

    f = open(current_directory + '/cro_data/valid_' + flag, 'w')
    for key, item in valid.items():
        if key[1] == -1:
            num += 1
            continue
        write_str = key[0] + ' ' + str(key[1]) + ' valid: '
        for temp in item:
            write_str += '[' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '
        f.write(write_str + '\n')
    f.close()

    f = open(current_directory + '/cro_data/unknown_' + flag, 'w')
    for key, item in unknown.items():
        if key[1] == -1:
            num += 1
            continue
        write_str = key[0] + ' ' + str(key[1])
        f.write(write_str + '\n')
    f.close()
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        log.write(f"{num} routes with as-set, do not retificate.\n")
    return invalid, unknown

def main():
    

    cro_file = "/home/demo/multi_source_data/" + yesterday + "/cro_data/cro_mdis_initial_" + yesterday

    start_time = datetime.now()
    start_timetamp = start_time.strftime("%Y%m%d %H:%M:%S")
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        log.write(f"{start_timetamp} generate_invalid_unknown started, {cro_file}\n")
        


    spemap_v4 = {}
    spemap_v6 = {}
    getspemap(spemap_v4, spemap_v6, private_ip_list_v4, private_ip_list_v6)

    data_bgp = {}
    year = current_directory.split('-')[0]
    month = current_directory.split('-')[1]
    day = current_directory.split('-')[2]
    timestamp = year+month+day
    if content == 'local':
        process_bgp_local('/home/demo/route_analyze/' + current_directory + '/parsed-rib-ipv4', data_bgp, spemap_v4, spemap_v6)
        process_bgp_local('/home/demo/route_analyze/' + current_directory + '/parsed-rib-ipv6', data_bgp, spemap_v4, spemap_v6)
    elif content == 'rib':
        process_bgp('/home/demo/multi_source_data/' + current_directory + '/bgp_route/checklog/total/total-json-'+timestamp+'-nopch.json', data_bgp, spemap_v4, spemap_v6)

    roa_file = '/home/demo/route_analyze/' + yesterday + "/roa_data/" + yesterday + "-0000" 
    
    if not os.path.exists(roa_file):
        roa_file = "/home/demo/multi_source_data/"  + yesterday + "/roa_data/" + yesterday + "-0000" 
    
    data_roa, data_roa_asn = read_CRO(roa_file)
    roa_results_v4, roa_results_v6, invalid, unknown, valid = rov(data_bgp, data_roa, spemap_v4, spemap_v6, 'temp')
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        log.write(f"roa-ipv4: {roa_results_v4[0]}, {roa_results_v4[1]}, {roa_results_v4[2]}, {roa_results_v4[3]}\n")
        log.write(f"roa-ipv6: {roa_results_v6[0]}, {roa_results_v6[1]}, {roa_results_v6[2]}, {roa_results_v6[3]}\n")
    print("roa: ", roa_results_v4, roa_results_v6)


    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        duration = finish_time - start_time
        log.write(f"{finish_timestamp} generate_invalid_unknown ended\n")
    

if __name__ == "__main__":
    main()