from matplotlib_venn import venn2, venn2_circles, venn3, venn3_circles
import matplotlib.pyplot as plt
from source_analysis import checkspepfx, checkspeasn, private_ip_list_v4, private_ip_list_v6
from source_analysis import getspemap, getroamap, getpfxmap, getpfxbin
from irr_filter import process_irr
import sys
from datetime import datetime, timedelta
import json
from math import pi
import numpy as np
from matplotlib.patches import Patch
from matplotlib.lines import Line2D
import re
import copy

current_directory = sys.argv[1]
#cro_file = current_directory + "/cro_data/cro_" + current_directory
cro_file = current_directory + "/cro_data/cro_mdis_initial_" + current_directory
roa_file = current_directory + '/roa_data/' + current_directory + '-0000'

def has_continuous_string(input_str, target_str):
    # ， re.IGNORECASE 
    pattern = re.compile(target_str, re.IGNORECASE)
    
    # 
    match = re.search(pattern, input_str)
    
    # 
    return bool(match)

def calculate_date(date_to_process, check_day):
    date_object = datetime.strptime(date_to_process, '%Y-%m-%d')
    bgpdate = []
    #  check_day 
    result_date = date_object + timedelta(days=check_day)
    return result_date.strftime('%Y-%m-%d')

def process_bgp_total(file, data):
    f1 = open(file, 'r')
    i = 0
    for line in f1:
        if i == 0:
            num = int(line.split('\n')[0])
            i = 1
            continue
        line_list = line.split(' ')
        prefix = line_list[1]
        asn = int(line_list[0])
        day = int(line_list[3].split('\n')[0])
        if (prefix, asn) not in data:
            data[(prefix, asn)] = day
    return num

def read_CRO(file_name=cro_file):
    f1 = open(file_name, 'r')
    print(file_name)
    index = -1

    result = {}
    result['ROA'] = set()
    result['roa_aggregate'] = set()
    result['roa_new'] = set()
    result['IRR'] = set()
    result['BGP'] = set()
    
    tal = {}
    tal_key = ['AFRINIC', 'APNIC', 'ARIN', 'LACNIC', 'RIPE']
    tal['APNIC'] = 0
    tal['ARIN'] = 0
    tal['AFRINIC'] = 0
    tal['LACNIC'] = 0
    tal['RIPE'] = 0
    
    num_v4 = 0
    num_v6 = 0

    data = {}

    for line in f1:
        if "asn" not in line:
            continue
        asn = int(line.split("asn\": \"")[1].split("\"")[0][2:])
        prefix = line.split("prefix\": \"")[1].split("\"")[0]
        maxLength = int(line.split("maxLength\": ")[1].split(",")[0])
        ty_pe = line.split("type\": \"")[1].split("\"")[0]
        talist = line.split("tal\": \"")[1].split("\"")[0]
        index += 1
        type_list = ty_pe.split(', ')
        for type_temp in type_list:
            if type_temp == 'CRO_correction':
                continue
            result[type_temp].add(index)
        if '.' in prefix:
            num_v4 += 1
        elif ':' in prefix:
            num_v6 += 1
        
        if (prefix, asn, maxLength) not in data:
            data[(prefix, asn, maxLength)] = {}
            data[(prefix, asn, maxLength)]['source'] = ty_pe
            data[(prefix, asn, maxLength)]['valid'] = []
            data[(prefix, asn, maxLength)]['invalid'] = []
        
        tal_list = talist.split(', ')[0]
        for key in tal_key:
            if has_continuous_string(tal_list, key):
                tal[key] += 1
        
    f1.close()
    return result, tal, num_v4, num_v6, data

def analysis_v4_v6(num_v4, num_v6, data_bgp, data_roa):
    f = open(current_directory+'/analysis/result/mdis_CRO_analysis', 'w')
    print("IPv4: " + str(num_v4) + " IPv6: " + str(num_v6))
    f.write('{\"IPv4\": \"' + str(num_v4) + '\", \"IPv6\": \"' + str(num_v6) + '\",\n')
    f.close()

def rovproc(roamap, pfx, length, asnset, pfxstr, data_bgp, data_roa):
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
                    data_bgp[(pfxstr, asn)]['valid'].append([v['vrp'], asn, maxlen, data_roa[(v['vrp'], asn, maxlen)]['source']])
                    #data_roa[(v['vrp'], asn, maxlen)]['valid'].append([pfxstr, asn])
                elif asn != asnset:
                    data_bgp[(pfxstr, asnset)]['invalid'].append([v['vrp'], asn, maxlen, data_roa[(v['vrp'], asn, maxlen)]['source']])
                    #data_roa[(v['vrp'], asn, maxlen)]['invalid'].append([pfxstr, asnset])
                    invalid_list.append('invalid_asn')
                else:
                    data_bgp[(pfxstr, asnset)]['invalid'].append([v['vrp'], asn, maxlen, data_roa[(v['vrp'], asn, maxlen)]['source']])
                    #data_roa[(v['vrp'], asn, maxlen)]['invalid'].append([pfxstr, asnset])
                    invalid_list.append('invalid_maxlen')
    
    if pfx_exists and r!= 'valid':
        if 'invalid_asn' in invalid_list:
            r = 'invalid_asn'
        elif 'invalid_maxlen' in invalid_list:
            r = 'invalid_maxlen'
    
    data_bgp[(pfxstr, asnset)]['result'] = r

    return r


def rov(data_bgp, data_roa, spemap_v4, spemap_v6):
    results = ['valid', 'invalid_asn', 'invalid_maxlen', 'unknown']
    results_v4 = [0,0,0,0]
    results_v6 = [0,0,0,0]
    invalid = {}
    unknown = {}
    results_t = {}

    roamap_v4 = {}
    roamap_v6 = {}
    pfxmap_v4 = {}
    pfxmap_v6 = {}
    getroamap(roamap_v4, roamap_v6, data_roa)
    getpfxmap(pfxmap_v4, pfxmap_v6, data_bgp)

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
                r_roa = rovproc(roamap_v6, pfx, pl, asns, pfxstr, data_bgp, data_roa)
                results_v6[results.index(r_roa)] += 1
                if 'invalid' in r_roa:
                    invalid[(pfxstr, asn)] = data_bgp[(pfxstr, asn)]['invalid']
                if 'unknown' in r_roa:
                    unknown[(pfxstr, asn)] = {}
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
                r_roa = rovproc(roamap_v4, pfx, pl, asns, pfxstr, data_bgp, data_roa)
                results_v4[results.index(r_roa)] += 1
                if 'invalid' in r_roa:
                    invalid[(pfxstr, asn)] = data_bgp[(pfxstr, asn)]['invalid']
                if 'unknown' in r_roa:
                    unknown[(pfxstr, asn)] = {}
                results_t[(pfxstr, asn)] = r_roa
    
    return results_v4, results_v6, invalid, unknown

def rov_irr(data_bgp, data_irr, spemap_v4, spemap_v6):
    results = ['valid', 'invalid', 'unknown']
    results_v4 = [0,0,0]
    results_v6 = [0,0,0]

    roamap_v4 = {}
    roamap_v6 = {}
    pfxmap_v4 = {}
    pfxmap_v6 = {}
    getroamap(roamap_v4, roamap_v6, data_irr)
    getpfxmap(pfxmap_v4, pfxmap_v6, data_bgp)

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
                r_roa = rovproc_irr(roamap_v6, pfx, pl, asns, pfxstr, data_bgp, data_irr)
                results_v6[results.index(r_roa)] += 1
    

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
                r_roa = rovproc_irr(roamap_v4, pfx, pl, asns, pfxstr, data_bgp, data_irr)
                results_v4[results.index(r_roa)] += 1
    
    return results_v4, results_v6


def process_roa(file):
    f1 = open(file, 'r')
    print(file)
    data = {}

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
        
    f1.close()
    return data

def process_bgp(file, data, spemap_v4, spemap_v6):
    with open(file, 'r') as file:
        json_data = json.load(file)

    #  "asn"  "Prefix" 
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
            data[(prefix, asn)]['valid'] = []
            data[(prefix, asn)]['invalid'] = []
        

def process_bgp_cad(file, data, spemap_v4, spemap_v6):
    try:
        with open(file, 'r') as f:
            file_content = f.read()
    except:
        return

    strings = eval(file_content)  #  eval 
    for temp in strings:
        asn = int(temp.split(' ')[0])
        prefix = temp.split(' ')[1]
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
        #if prefix == '2001:b00::8/128':
            #print(temp)
        if (prefix, asn) not in data:
            data[(prefix, asn)] = {}
            data[(prefix, asn)]['num'] = 1
            data[(prefix, asn)]['valid'] = []
            data[(prefix, asn)]['invalid'] = []

def plot_stacked_bar(valid, invalid, unknown, name):
    '''
    # 
    valid = [0.2, 0.3, 0.4]  #  valid 
    invalid = [0.1, 0.2, 0.1]  #  invalid 
    unknown = [0.7, 0.5, 0.5]  #  unknown 
    '''
    print(name, valid, invalid, unknown)
    # 1
    total = [1] * len(valid)

    # 
    fig, ax = plt.subplots()

    ax.bar(range(len(valid)), valid, label='Valid', color='#4393E5', edgecolor='black', linewidth=1)
    ax.bar(range(len(invalid)), invalid, bottom=valid, label='Invalid', color='#F4B183', edgecolor='black', linewidth=1)
    ax.bar(range(len(unknown)), unknown, bottom=[i+j for i, j in zip(valid, invalid)], label='Unknown', color='gray', edgecolor='black', linewidth=1)

    # 
    ax.set_xticks(range(len(total)))
    ax.set_xticklabels(['RPKI ROA', 'IRR', 'MDIS CRO'])
    ax.set_ylabel('Validation Result Proportion')
    ax.set_title('Comparison of Methods')

    # 
    ax.legend()

    # 
    plt.savefig(current_directory+'/analysis/figure/mdis_validate_compare_' + name + '.pdf')
    plt.close()

def plot_circle(ipv4, ipv6, flag):
    fig, ax = plt.subplots(figsize=(6, 6))
    ax = plt.subplot(projection='polar')
    #ipv4 = [0.8, 0.1, 0.05]
    #ipv6 = [0.75, 0.15, 0.1]
    data = [ipv4, ipv6]
    startangle = 90
    colors = ['#4393E5', '#7AE6EA'] #, '#43BAE5'
    colors_invalid = ['#F4B183', '#FBE5D6']
    colors_unknown = ['#BFBFBF', '#D9D9D9']
    #xs = [(i * pi *2)/ 100 for i in data]
    ys = [1, 2.2]
    left = (startangle * pi *2)/ 360 #this is to control where the bar starts
    # plot bars and points at the end to make them round
    for i, x in enumerate(ys):
        ax.barh(ys[i], pi *2, left=left, height=1, color=colors_unknown[i])
        ax.barh(ys[i], data[i][0]* pi *2, left=left, height=1, color=colors[i])
        ax.barh(ys[i], data[i][1]* pi *2, left=data[i][0]* pi *2 +left, height=1, color=colors_invalid[i])
        ax.scatter(data[i][1]* pi *2 + data[i][0]* pi *2 +left, ys[i], s=350, color=colors_invalid[i], zorder=2)
        ax.scatter(left, ys[i], s=350, color=colors[i], zorder=2)
        
    plt.ylim(-4, 4)
    plt.xticks([])
    plt.yticks([])
    # legend
    legend_elements = [Line2D([0], [0], marker='o', color='w', label='IPv4 Valid        ' + str(round(ipv4[0] * 100, 2)) + '%', markerfacecolor='#4393E5', markersize=10),
                    Line2D([0], [0], marker='o', color='w', label='IPv4 Invalid     ' + str(round(ipv4[1] * 100, 2)) + '%', markerfacecolor='#F4B183', markersize=10),
                    Line2D([0], [0], marker='o', color='w', label='IPv4 Unknown ' + str(round(ipv4[2] * 100, 2)) + '%', markerfacecolor='#BFBFBF', markersize=10),
                    Line2D([0], [0], marker='o', color='w', label='IPv6 Valid        ' + str(round(ipv6[0] * 100, 2)) + '%', markerfacecolor='#7AE6EA', markersize=10),
                    Line2D([0], [0], marker='o', color='w', label='IPv6 Invalid     ' + str(round(ipv6[1] * 100, 2)) + '%', markerfacecolor='#FBE5D6', markersize=10),
                    Line2D([0], [0], marker='o', color='w', label='IPv6 Unknown ' + str(round(ipv6[2] * 100, 2)) + '%', markerfacecolor='#D9D9D9', markersize=10)]
    ax.legend(handles=legend_elements, loc='center', frameon=False)
    # clear ticks, grids, spines

    ax.spines.clear()
    plt.savefig(current_directory+'/analysis/figure/mdis_ipv4_ipv6' + flag + '.pdf')
    plt.savefig('cro_data/figure/ipv4_ipv6.pdf')
    plt.close()

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
            #print(pl, t)
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

def process_special_org(file):
    security_list = []
    f1 = open(file, 'r', encoding = "ISO-8859-1")
    for line in f1:
        security_list.append(line.split('\n')[0].split('|')[0])
    f1.close()
    return security_list

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

def process_as_org(caida_file, data_as_org, data_as_country):
    
    as2org = {}
    org2country = {}
    process_as_country(caida_file, as2org, org2country)
    for asn in as2org:
        data_as_country[asn] = org2country[as2org[asn]]
    
    return as2org

def get_notsure_score(key, irrmap_v4, irrmap_v6, roamap_v4, roamap_v6, data_bgp_total, bgp_day_max, as2org, security_org, whitelist_org, flag, f_invalid, f_unknown, item):
    score = 0
    #irr
    r_rov = rov_single(key, irrmap_v4, irrmap_v6, 'irr')
    
    if r_rov == 'valid':
        score += 100

    #roa
    roa_rov = rov_single(key, roamap_v4, roamap_v6, 'roa')

    #bgp day
    if key in data_bgp_total:
        day = data_bgp_total[key]
    else:
        day = 0
    
    if day > bgp_day_max * 0.8:
        score += 100
    
    #security service
    try:
        if as2org[int(key[1])] in security_org:
            securityservice = 1
        else:
            securityservice = 0
    except:
        securityservice = 0
    
    #whitelist
    try:
        if as2org[int(key[1])] in whitelist_org:
            whitelist = 1
        else:
            whitelist = 0
    except:
        whitelist = 0
    

    #write
    if flag == 'invalid':
        write_str = key[0] + ', ' + str(key[1]) + ', ' + roa_rov  + ', ' + r_rov + ', ' + str(day) + ', ' + str(securityservice) + ', ' + str(whitelist)  + ', invalid: '
        for temp in item:
            write_str += '[' + temp[0] + ', ' + str(temp[1]) + ', ' + str(temp[2]) + ', ' + temp[3] + '] '
        f_invalid.write(write_str + '\n') 
    elif flag == 'unknown':
        write_str = key[0] + ', ' + str(key[1]) + ', ' + r_rov + ', ' + str(day)
        f_unknown.write(write_str + '\n')
    

def analysis_reason(invalid, unknown, spemap_v4, spemap_v6):
    #step-c irr
    data_irr = {}
    process_irr(current_directory + '/irr_data/irr-route-total-' + current_directory, data_irr, spemap_v4, spemap_v6)
    process_irr(current_directory + '/irr_data/irr-route6-total-' + current_directory, data_irr, spemap_v4, spemap_v6)
    irrmap_v4 = {}
    irrmap_v6 = {}
    getroamap(irrmap_v4, irrmap_v6, data_irr)

    #step-c roa
    data_roa = process_roa(roa_file)
    roamap_v4 = {}
    roamap_v6 = {}
    getroamap(roamap_v4, roamap_v6, data_roa)

    #step-c bgp_frequency
    data_bgp_total = {}
    bgp_day_max = process_bgp_total('/home/demo/multi_source_data/' + current_directory+'/bgp_filter_data/bgp_frequency', data_bgp_total)
    
    data_as_org = {}
    data_as_country = {}
    as2org = process_as_org('CAIDA/as_org/as-org2info.jsonl', data_as_org, data_as_country)

    security_org = process_special_org('/home/demo/route_analyze/CAIDA/as_org/securityservice')
    whitelist_org = process_special_org('/home/demo/route_analyze/CAIDA/as_org/whitelist')
    
    f_invalid = open(current_directory + '/analysis/invalid_reason', 'w')
    f_unknown = open(current_directory + '/analysis/unknown_reason', 'w')
    
    write_str = 'prefix' + ', ' + 'ASN' + ', ' + 'roa_result'  + ', ' + 'irr_result' + ', ' + 'day_in_bgp_table' + ', ' + 'just_maxlength'  + ', ' + 'reachable' + ', ' + 'Country' + ', ' + 'score'  + ', ' + 'SecurityService'  + ', ' + 'WhiteList' + ', invalid_reason'
    f_invalid.write(write_str + '\n')

    write_str = 'prefix' + ', ' + 'ASN'
    f_unknown.write(write_str + '\n')

    num_yes = 0
    num_invalid = 0

    for key, item in unknown.items():
        get_notsure_score(key, irrmap_v4, irrmap_v6, roamap_v4, roamap_v6, data_bgp_total, bgp_day_max, as2org, security_org, whitelist_org, 'unknown', f_invalid, f_unknown, item)

    for key, item in invalid.items():
        get_notsure_score(key, irrmap_v4, irrmap_v6, roamap_v4, roamap_v6, data_bgp_total, bgp_day_max, as2org, security_org, whitelist_org, 'invalid', f_invalid, f_unknown, item)

    f_unknown.close()
    f_invalid.close()
    

def analyze_validate(data_roa, data_bgp, spemap_v4, spemap_v6, flag=''):

    results_v4, results_v6, invalid, unknown = rov(data_bgp, data_roa, spemap_v4, spemap_v6)
    print("cro: ", results_v4, results_v6)

    #  A, B, C
    data_sources = ['Valid', 'Invalid', 'Unknown']
    # 
    data_counts = [results_v4[0], results_v4[1] + results_v4[2], results_v4[3]]
    # 
    fig, ax = plt.subplots(figsize=(6, 6))
    plt.pie(data_counts, labels=data_sources, autopct='%1.1f%%', startangle=90, colors=['#DAE3F3', '#E2F0D9', '#FBE5D6']) #colors=['skyblue', 'lightgreen', 'lightcoral'])
    # 
    plt.title('ROV result for IPv4 BGP Route')
    plt.savefig(current_directory+'/analysis/figure/mdis_rov_ipv4'+ flag +'.pdf')
    plt.savefig('cro_data/figure/rov_ipv4.pdf')
    plt.close()

    data_counts = [results_v6[0], results_v6[1] + results_v6[2], results_v6[3]]
    # 
    fig, ax = plt.subplots(figsize=(6, 6))
    plt.pie(data_counts, labels=data_sources, autopct='%1.1f%%', startangle=90, colors=['#DAE3F3', '#E2F0D9', '#FBE5D6']) #colors=['skyblue', 'lightgreen', 'lightcoral'])
    # 
    plt.title('ROV result for IPv6 BGP Route')
    plt.savefig(current_directory+'/analysis/figure/mdis_rov_ipv6'+ flag +'.pdf')
    plt.savefig('cro_data/figure/rov_ipv6.pdf')
    plt.close()

    ipv4 = []
    total_num = results_v4[0] + results_v4[1] + results_v4[2] + results_v4[3]
    ipv4 = [results_v4[0] / total_num, (results_v4[1] + results_v4[2]) / total_num, results_v4[3] / total_num]
    ipv6 = []
    total_num = results_v6[0] + results_v6[1] + results_v6[2] + results_v6[3]
    ipv6 = [results_v6[0] / total_num, (results_v6[1] + results_v6[2]) / total_num, results_v6[3] / total_num]

    plot_circle(ipv4, ipv6, flag)

    if flag == '':
        analysis_reason(invalid, unknown, spemap_v4, spemap_v6)


    return results_v4, results_v6


def rovproc_irr(roamap, pfx, length, asnset, pfxstr, data_bgp, data_irr):
    r = 'unknown'
    pfx_exists = False
    for pl in range(length, -1, -1):
        # length is route ip length, so irr length <= length
        if pl not in roamap:
            continue
        t = pfx[:pl]
        if t in roamap[pl]:
            vrpset = roamap[pl][t]
            n = vrpset['num']
            vrps = vrpset['vrps']
            for i in range(n):
                v = vrps[i]
                maxlen = v['maxlen']
                asn = v['asn']
                if pl == length and asn == asnset:
                    r = 'valid'
                if pl == length:
                    pfx_exists = True

    if pfx_exists and r!= 'valid':
        r = 'invalid'

    return r

def compare_validate(data_bgp, spemap_v4, spemap_v6, results_v4, results_v6):
    cro_results_v4 = results_v4
    cro_results_v6 = results_v6
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        log.write(f"cro-ipv4: {results_v4[0]}, {results_v4[1]}, {results_v4[2]}, {results_v4[3]}\n")
        log.write(f"cro-ipv6: {results_v6[0]}, {results_v6[1]}, {results_v6[2]}, {results_v6[3]}\n")

    data_roa = process_roa(roa_file)
    roa_results_v4, roa_results_v6, invalid_list, unknown_list = rov(data_bgp, data_roa, spemap_v4, spemap_v6)
    analyze_validate(data_roa, data_bgp, spemap_v4, spemap_v6, '_roa')
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        log.write(f"roa-ipv4: {roa_results_v4[0]}, {roa_results_v4[1]}, {roa_results_v4[2]}, {roa_results_v4[3]}\n")
        log.write(f"roa-ipv6: {roa_results_v6[0]}, {roa_results_v6[1]}, {roa_results_v6[2]}, {roa_results_v6[3]}\n")
    print("roa: ", roa_results_v4, roa_results_v6)

    data_irr = {}
    process_irr(current_directory + '/irr_data/irr-route-total-' + current_directory, data_irr, spemap_v4, spemap_v6)
    process_irr(current_directory + '/irr_data/irr-route6-total-' + current_directory, data_irr, spemap_v4, spemap_v6)
    irr_results_v4, irr_results_v6 = rov_irr(data_bgp, data_irr, spemap_v4, spemap_v6)
    print("irr: ", irr_results_v4, irr_results_v6)

    valid = [roa_results_v4[0] / sum(roa_results_v4), irr_results_v4[0] / sum(irr_results_v4), cro_results_v4[0] / sum(cro_results_v4)]
    invalid = [(roa_results_v4[1] + roa_results_v4[2]) / sum(roa_results_v4), irr_results_v4[1] / sum(irr_results_v4), (cro_results_v4[1] + cro_results_v4[2]) / sum(cro_results_v4)]
    unknown = [roa_results_v4[3] / sum(roa_results_v4), irr_results_v4[2] / sum(irr_results_v4), cro_results_v4[3] / sum(cro_results_v4)]
    plot_stacked_bar(valid, invalid, unknown, 'ipv4')

    valid = [roa_results_v6[0] / sum(roa_results_v6), irr_results_v6[0] / sum(irr_results_v6), cro_results_v6[0] / sum(cro_results_v6)]
    invalid = [(roa_results_v6[1] + roa_results_v6[2]) / sum(roa_results_v6), irr_results_v6[1] / sum(irr_results_v6), (cro_results_v6[1] + cro_results_v6[2]) / sum(cro_results_v6)]
    unknown = [roa_results_v6[3] / sum(roa_results_v6), irr_results_v6[2] / sum(irr_results_v6), cro_results_v6[3] / sum(cro_results_v6)]
    plot_stacked_bar(valid, invalid, unknown, 'ipv6')

    valid = [(roa_results_v4[0] + roa_results_v6[0]) / (sum(roa_results_v4) + sum(roa_results_v6)), (irr_results_v4[0] + irr_results_v6[0]) / (sum(irr_results_v4) + sum(irr_results_v6)), (cro_results_v4[0] + cro_results_v6[0]) / (sum(cro_results_v4) + sum(cro_results_v6))]
    invalid = [(roa_results_v4[1] + roa_results_v4[2] + roa_results_v6[1] + roa_results_v6[2]) / (sum(roa_results_v4) + sum(roa_results_v6)), (irr_results_v4[1] + irr_results_v6[1]) / (sum(irr_results_v4) + sum(irr_results_v6)), (cro_results_v4[1] + cro_results_v4[2] + cro_results_v6[1] + cro_results_v6[2]) / (sum(cro_results_v4) + sum(cro_results_v6))]
    unknown = [(roa_results_v4[3] + roa_results_v6[3]) / (sum(roa_results_v4) + sum(roa_results_v6)), (irr_results_v4[2] + irr_results_v6[2]) / (sum(irr_results_v4) + sum(irr_results_v6)), (cro_results_v4[3] + cro_results_v6[3]) / (sum(cro_results_v4) + sum(cro_results_v6))]
    plot_stacked_bar(valid, invalid, unknown, 'total')

    return invalid_list, unknown_list

    


def plot_venn(result):
    
    name_list = []
    result_list = []
    for key in result:
        name_list.append(key)
        result_list.append(result[key])
    set_A = result['ROA'].union(result['roa_new']).union(result['roa_aggregate'])
    set_B = result['IRR']
    set_C = result['BGP']
    color_A = "skyblue" #"mediumblue" #skyblue"
    color_B = "lightgreen" #"darkgreen" #"lightgreen"
    color_C = "lightcoral" #"crimson" #"lightcoral"
    fig, ax = plt.subplots(figsize=(6, 4))
    venn_diagram = venn3([set_A, set_B, set_C], set_labels=('ROA', 'IRR', 'BGP'), set_colors=(color_A, color_B, color_C), alpha=0.5)
    venn3_circles(subsets=(len(set_A - set_B - set_C),
                        len(set_B - set_A - set_C),
                        len(set_A & set_B - set_C),
                        len(set_C - set_A - set_B),
                        len(set_A & set_C - set_B),
                        len(set_B & set_C - set_A),
                        len(set_A & set_B & set_C)),
                linestyle='solid', linewidth=1.0, color="white")
    total_num = len(set_A | set_B | set_C)
    f = open(current_directory+'/analysis/result/mdis_CRO_analysis', 'a')
    f.write('\"Total CRO num\": \"' + str(total_num) + '\"}\n')
    f.close()
    venn_diagram.get_label_by_id('100').set_text('ROA only: ' + str(int(len(set_A - set_B - set_C) / total_num * 100)) + '%')
    venn_diagram.get_label_by_id('010').set_text('IRR only: ' + str(int(len(set_B - set_A - set_C) / total_num * 100)) + '%')
    venn_diagram.get_label_by_id('001').set_text('BGP only: ' + str(int(len(set_C - set_A - set_B) / total_num * 100)) + '%')
    venn_diagram.get_label_by_id('110').set_text('ROA ∩ IRR: ' + str(int(len(set_A & set_B - set_C) / total_num * 100)) + '%')
    venn_diagram.get_label_by_id('101').set_text('ROA ∩ BGP: ' + str(int(len(set_A & set_C - set_B) / total_num * 100)) + '%')
    venn_diagram.get_label_by_id('011').set_text('IRR ∩ BGP: ' + str(int(len(set_B & set_C - set_A) / total_num * 100)) + '%')
    venn_diagram.get_label_by_id('111').set_text('ALL: ' + str(int(len(set_A & set_B & set_C) / total_num * 100)) + '%')
    '''
    venn_diagram.get_patch_by_id('100').set_edgecolor('white')
    venn_diagram.get_patch_by_id('010').set_edgecolor('white')
    venn_diagram.get_patch_by_id('001').set_edgecolor('white')
    venn_diagram.get_patch_by_id('110').set_edgecolor('white')
    venn_diagram.get_patch_by_id('011').set_edgecolor('white')
    venn_diagram.get_patch_by_id('111').set_edgecolor('white')
    '''
    
    #plt.title('CRO Sources')
    plt.savefig(current_directory+'/analysis/figure/mdis_CRO_sources.pdf')
    plt.savefig('cro_data/figure/CRO_sources.pdf')
    plt.close()

    print(len(set_A - set_B - set_C) / total_num * 100)
    print(len(set_B - set_A - set_C) / total_num * 100)
    print(len(set_C - set_A - set_B) / total_num * 100)
    print(len(set_A & set_B - set_C) / total_num * 100)
    print(len(set_A & set_C - set_B) / total_num * 100)
    print(len(set_B & set_C - set_A) / total_num * 100)
    print(len(set_A & set_B & set_C) / total_num * 100)
    

def analyze_tal(tal):
    total_num = 0
    for key in tal:
        total_num += tal[key]
    tal_key = ['AFRINIC', 'APNIC', 'ARIN', 'LACNIC', 'RIPE']
    data_counts = [tal[tal_key[0]] / total_num, tal[tal_key[1]] / total_num, tal[tal_key[2]] / total_num, tal[tal_key[3]] / total_num, tal[tal_key[4]] / total_num]
    # 
    plt.pie(data_counts, labels=tal_key, autopct='%1.1f%%', startangle=90, colors=['#F4DCFF', '#DAE3F3', '#E2F0D9', '#FBE5D6', '#FEF2CC']) #colors=['skyblue', 'lightgreen', 'lightcoral'])
    # 
    plt.title('Trust Anchors')
    plt.savefig(current_directory+'/analysis/figure/mdis_tal.pdf')
    plt.savefig('cro_data/figure/tal.pdf')
    plt.close()

def roa_invalid_now_cro(invalid, data_bgp_cro, data_cro, flag):
    f = open(current_directory+'/analysis/result/roa_'+flag+'_cro_now', 'w')
    f.write('{\"routes\": [')
    for key in invalid:
        result = data_bgp_cro[key]['result']
        if result == 'valid':
            sources = []
            for roa in data_bgp_cro[key]['valid']:
                source_list = data_cro[(roa[0], roa[1], roa[2])]['source'].split(', ')
                for temp in source_list:
                    if temp not in sources:
                        sources.append(temp)
            source = ''
            for temp in sources:
                source += temp + ', '
            source = source[:-2]
            f.write('{\"BGP Route Prefix\": \"' + key[0] + '\", \"ASN\": \"AS' + str(key[1]) + '\", \"Result\": \"' + result + '\", \"Source\": \"' + source + '\"},\n')
        else:
            f.write('{\"BGP Route Prefix\": \"' + key[0] + '\", \"ASN\": \"AS' + str(key[1]) + '\", \"Result\": \"' + result + '\", \"Source\": ' + '' + '\"\"},\n')
    f.close()

    with open(current_directory+'/analysis/result/roa_'+flag+'_cro_now', 'r') as file:
        lines = file.readlines()

    # 
    if lines:
        # ，
        last_line = lines[-1].rstrip('\n,')  # 
        lines[-1] = last_line + '\n'

        # 
        with open(current_directory+'/analysis/result/roa_'+flag+'_cro_now', 'w') as file:
            file.writelines(lines)
            file.write("]}\n")
    



def main():
    start_time = datetime.now()
    start_timetamp = start_time.strftime("%Y%m%d %H:%M:%S")
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        log.write(f"{start_timetamp} cro analyze fig started\n")

    result, tal, num_v4, num_v6, data_cro = read_CRO()
    spemap_v4 = {}
    spemap_v6 = {}
    getspemap(spemap_v4, spemap_v6, private_ip_list_v4, private_ip_list_v6)

    data_bgp = {}
    #process_bgp_cad('/home/cad/rpki/bgpdump/list/total-list-20231210', data_bgp, spemap_v4, spemap_v6)
    year = current_directory.split('-')[0]
    month = current_directory.split('-')[1]
    day = current_directory.split('-')[2]
    timestamp = year+month+day
    process_bgp(current_directory+'/bgp_route/checklog/total/total-json-'+timestamp+'-nopch.json', data_bgp, spemap_v4, spemap_v6)
    print(len(data_bgp))
    

    #step 2
    analysis_v4_v6(num_v4, num_v6, data_bgp, data_cro)

    #step 3
    results_v4, results_v6 = analyze_validate(data_cro, data_bgp, spemap_v4, spemap_v6)
    data_bgp_cro = copy.deepcopy(data_bgp) #reserve the cro validate result
 
    #step 4
    analyze_tal(tal)

    #step 1
    plot_venn(result)

    #step 5
    invalid, unknown = compare_validate(data_bgp, spemap_v4, spemap_v6, results_v4, results_v6)

    #step 6
    roa_invalid_now_cro(invalid, data_bgp_cro, data_cro, 'invalid')
    roa_invalid_now_cro(unknown, data_bgp_cro, data_cro, 'unknown')

    
    #step 7 yesterday
    '''
    data_bgp = {}
    tomorrow = calculate_date(current_directory, 1)
    year = tomorrow.split('-')[0]
    month = tomorrow.split('-')[1]
    day = tomorrow.split('-')[2]
    timestamp = year+month+day
    process_bgp(tomorrow+'/bgp_route/checklog/total/total-json-'+timestamp+'.json', data_bgp, spemap_v4, spemap_v6)
    '''
    '''
    yesterday = calculate_date(current_directory, -1)
    file_name = yesterday + "/cro_data/cro_mdis_initial_" + yesterday
    result, tal, num_v4, num_v6, data_cro = read_CRO(file_name)
    results_v4, results_v6 = analyze_validate(data_cro, data_bgp, spemap_v4, spemap_v6, '_tmr')
    '''

    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        duration = finish_time - start_time
        log.write(f"{finish_timestamp} cro analyze fig ended\n")
    

if __name__ == "__main__":
    main()