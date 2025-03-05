import matplotlib.pyplot as plt
import numpy as np
import copy
import time
import ipaddress
import json
import os
import sys
from datetime import datetime, timedelta

private_ip_list_v4 = [
        '0.0.0.0/8',
        '0.0.0.0/32',
        '10.0.0.0/8',
        '100.64.0.0/10',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '172.16.0.0/12',
        '192.0.0.0/24',
        '192.0.0.0/29',
        '192.0.0.8/32',
        '192.0.0.9/32',
        '192.0.0.10/32',
        '192.0.0.170/32',
        '192.0.0.171/32',
        '192.0.2.0/24',
        '192.31.196.0/24',
        '192.52.193.0/24',
        '192.88.99.0/24',
        '192.168.0.0/16',
        '192.175.48.0/24',
        '198.18.0.0/15',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4',
        '233.252.0.0/24',
        '240.0.0.0/4',
        '255.255.255.255/32']

private_ip_list_v6 = [
        '::1/128',
        '::/128',
        '::ffff:0:0/96',
        '64:ff9b::/96',
        '64:ff9b:1::/48',
        '100::/64',
        '2001::/23',
        '2001::/32',
        '2001:1::1/128',
        '2001:1::2/128',
        '2001:2::/48',
        '2001:3::/32',
        '2001:4:112::/48',
        '2001:10::/28',
        '2001:20::/28',
        '2001:30::/28',
        '2001:db8::/32',
        '2002::/16',
        '2620:4f:8000::/48',
        'fc00::/7',
        'fe80::/10',
        '2000::/3',
        'ff00::/8']

def write_data_to_file(data1, filename):
    # filename = "output.json"
    with open(filename, "a") as file:
        json.dump(data1, file)
        file.write('\n')  # 

def createROAmap(roamap, asn, pfxstr, maxlen):
    pfx = pfxstr.split('/')
    ip = pfx[0]
    length= int(pfx[1])
    if length not in roamap:
        roamap[length] = {}
    pfxbin = getpfxbin(ip, length)
    if pfxbin not in roamap[length]:
        roamap[length][pfxbin] = {}
        r = roamap[length][pfxbin]
        r['num'] = 0
        r['vrps'] = {}
    r = roamap[length][pfxbin]
    k = r['num']
    r['vrps'][k] = {}
    p = r['vrps'][k]
    p['vrp'] = pfxstr
    p['asn'] = asn
    p['maxlen'] = int(maxlen)
    r['num'] = k + 1

def checkspeasn(asns):
    try:
        asn = int(list(asns)[0])
    except:
        asn = int(asns)
    if asn == 0 or 64496 <= asn <= 131071 or 401309 <= asn <= 4294967295 or asn == 23456 or 153914 <= asn <= 196607 or 216476 <= asn <= 262143 or 274845 <= asn <= 327679 or 329728 <= asn <= 393215:
        return True
    else:
        return False

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

def getirrmap(irrmap_v4, irrmap_v6, data_irr):
    for key in data_irr:
        asn = int(key[1])
        pfx = key[0]
        maxlength = int(pfx.split('/')[1].split('\n')[0])
        """ for IPv6 routes """
        if ':' in pfx:
            createROAmap(irrmap_v6, asn, pfx, maxlength)
        else:
            createROAmap(irrmap_v4, asn, pfx, maxlength)

def getroamap(roamap_v4, roamap_v6, data_roa):
    for key in data_roa:
        asn = int(key[1])
        pfx = key[0]
        maxlen = key[2]
        """ for IPv6 ROA """
        if ':' in pfx:
            createROAmap(roamap_v6, asn, pfx, maxlen)
        else:
            createROAmap(roamap_v4, asn, pfx, maxlen)

def getpfxmap(pfxmap_v4, pfxmap_v6, data_bgp):
    for key in data_bgp:
        prefix = key[0]
        pfx = prefix.split('/')[0]
        pfxlen = int(prefix.split('/')[1].split('\n')[0])
        asns = int(key[1])
        
        """ for IPv6 ROA """
        if ':' in pfx:
            createpfxmap(pfxmap_v6, asns, pfx, pfxlen)
        else:
            createpfxmap(pfxmap_v4, asns, pfx, pfxlen)

def checkspepfx(spemap, pfx, length):
    pfx_exists = False
    for pl in range(length, -1, -1):
        if pl not in spemap:
            continue
        t = pfx[:pl]
        if t in spemap[pl]:
            pfx_exists = True
            return pfx_exists
    return pfx_exists


def process_bgp(file, data, spemap_v4, spemap_v6, bgp_exception):
    with open(file, 'r') as file:
        json_data = json.load(file)

    #  "asn"  "Prefix" 
    for route in json_data.get('routes', []):
        asn = int(route.get('asn'))
        prefix = route.get('prefix')
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
        if (prefix, asn) not in data:
            data[(prefix, asn)] = {}
            data[(prefix, asn)]['num'] = 1
            data[(prefix, asn)]['result'] = ''
            data[(prefix, asn)]['valid'] = []
            data[(prefix, asn)]['invalid'] = []
        else:
            data[(prefix, asn)]['num'] += 1

    for key, item in bgp_exception.items():
        if key in data:
            data.pop(key)


def process_bgp_exception(file, data):
    f1 = open(file, 'r')
    for line in f1:
        prefix = line.split(',')[1]
        asn = int(line.split(',')[2].split('\n')[0])
        day = line.split(',')[0]
        data[(prefix, asn)] = day
    f1.close()
    print(data)

def process_roa(f, data, spemap_v4, spemap_v6):
    f1 = open(f, 'r')
    for line in f1:
        if "asn" not in line:
            continue
        asn = int(line.split("asn\": \"")[1].split("\"")[0][2:])
        prefix = line.split("prefix\": \"")[1].split("\"")[0]
        maxlen = int(line.split("maxLength\": ")[1].split(",")[0])
        ty_pe = line.split("type\": \"")[1].split("\"")[0]
        source = line.split("tal\": \"")[1].split("\"")[0]
        '''
        pfx = prefix.split('/')[0]
        pl = int(prefix.split('/')[1])
        if ':' in pfx and checkspepfx(spemap_v6, pfx, pl)==True:
            continue
        if '.' in pfx and checkspepfx(spemap_v4, pfx, pl)==True:
            continue
        if checkspeasn(asn) == True:
            continue
        if prefix == '0.0.0.0/0' or prefix == '::/0':
            continue
        '''
        if (prefix, asn, maxlen) not in data:
            data[(prefix, asn, maxlen)] = {}
            data[(prefix, asn, maxlen)]['num'] = 1
            data[(prefix, asn, maxlen)]['source'] = 'ROA'
            data[(prefix, asn, maxlen)]['sub-source'] = source
            data[(prefix, asn, maxlen)]['valid'] = []
            data[(prefix, asn, maxlen)]['invalid'] = []
            data[(prefix, asn, maxlen)]['result'] = 'unknown'
        else:
            data[(prefix, asn, maxlen)]['num'] += 1
    f1.close()


""" route orgin validation based on ROAs """
def rovproc(roamap, pfx, length, asnset, pfxstr, data_bgp, data_roa, filenamebybgpdate):
    r = 'unknown'
    pfx_exists = False
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
                    #r = "%s %s %s %s" % ('valid ', v['vrp'], maxlen, asn)
                    r = 'valid'
                    data_bgp[(pfxstr, asn)]['valid'].append([v['vrp'], asn, maxlen, data_roa[(v['vrp'], asn, maxlen)]['source']])
                    #print((v, asn, maxlen))
                    #data_roa[(v['vrp'], asn, maxlen)]['valid'].append([pfxstr, asn])
                    data_line = {
                        "roaasn": asn,
                        "roaip": v['vrp'],
                        "roamaxlen": maxlen,
                        "bgpasn": asnset,
                        "bgpip": pfxstr,
                        "modebythisbgp": r
                    }
                    write_data_to_file(data_line, filenamebybgpdate)
                elif length <= maxlen:
                    r = 'invalid'
                    data_bgp[(pfxstr, asnset)]['invalid'].append([v['vrp'], asn, maxlen, data_roa[(v['vrp'], asn, maxlen)]['source']])
                    #data_roa[(v['vrp'], asn, maxlen)]['invalid'].append([pfxstr, asnset])
                    data_line = {
                        "roaasn": asn,
                        "roaip": v['vrp'],
                        "roamaxlen": maxlen,
                        "bgpasn": asnset,
                        "bgpip": pfxstr,
                        "modebythisbgp": r
                    }
                    write_data_to_file(data_line, filenamebybgpdate)
                else:
                    r = 'invalid'
                    data_bgp[(pfxstr, asnset)]['invalid'].append([v['vrp'], asn, maxlen, data_roa[(v['vrp'], asn, maxlen)]['source']])
                    #data_roa[(v['vrp'], asn, maxlen)]['invalid'].append([pfxstr, asnset])
                    data_line = {
                        "roaasn": asn,
                        "roaip": v['vrp'],
                        "roamaxlen": maxlen,
                        "bgpasn": asnset,
                        "bgpip": pfxstr,
                        "modebythisbgp": r
                    }
                    write_data_to_file(data_line, filenamebybgpdate)
                    #return r
                
    if pfx_exists and r!= 'valid':
        r = 'invalid'

    return r

def rov(data_bgp, data_irr, filenamebybgpdate = None):
    f = open(filenamebybgpdate, 'w')
    f.close()
    results = ['valid', 'invalid', 'unknown']
    results_v4 = [0,0,0]
    results_v6 = [0,0,0]
    invalid = {}
    results_t = {}

    irrmap_v4 = {}
    irrmap_v6 = {}
    pfxmap_v4 = {}
    pfxmap_v6 = {}
    # dict irrmap_v4[length][ip_bits] has ['num'](int) and ['vrps'](dict)
    # dict irrmap_v4[length][ip_bits]['vrps'][0, 1, ...] has ['vrp']('1.0.0.0/24'), ['asn'](int), ['maxlen'](int), ['num'](int)
    getroamap(irrmap_v4, irrmap_v6, data_irr)
    # dict pfxmap_v4[length][ip_bits] has ['prefix'](list of '1.0.0.0/24') and ['asns'](list of ints), bgp data
    getpfxmap(pfxmap_v4, pfxmap_v6, data_bgp)
    for pl in range(128, -1, -1):
        # for ip length from 128 to 0
        if pl not in pfxmap_v6:
            # if ip belongs to private ip, continue
            continue
        pfxs = pfxmap_v6[pl]
        for pfx in pfxs:
            # pfx is ip bits
            # for longest bgp route data
            asns_list = pfxs[pfx]['asns']
            pfxstr_list = pfxs[pfx]['prefix']
            for i in range(len(asns_list)):
                asns = asns_list[i]
                # int: an asn
                pfxstr = pfxstr_list[i]
                # '1.0.0.0/24'
                asn = int(asns)
                r_roa = rovproc(irrmap_v6, pfx, pl, asns, pfxstr, data_bgp, data_irr, filenamebybgpdate)
                data_bgp[(pfxstr, asn)]['result'] = r_roa
                '''
                # check every irr data for this bgp data
                results_v6[results.index(r_roa)] += 1
                if r_roa == 'invalid':
                    invalid[(pfxstr, asn)] = data_bgp[(pfxstr, asn)]['invalid']
                results_t[(pfxstr, asn)] = r_roa
                '''

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
                r_roa = rovproc(irrmap_v4, pfx, pl, asns, pfxstr, data_bgp, data_irr, filenamebybgpdate)
                data_bgp[(pfxstr, asn)]['result'] = r_roa
                '''
                results_v4[results.index(r_roa)] += 1
                if r_roa == 'invalid':
                    invalid[(pfxstr, asn)] = data_bgp[(pfxstr, asn)]['invalid']
                results_t[(pfxstr, asn)] = r_roa
                '''

    return results_v4, results_v6, invalid, results_t


def write_roa(data, new_f, day_num):
    f1 = open(new_f, 'w')
    f1.write(str(day_num) + '\n')
    for key, item in data.items():
        asn = key[1]
        prefix = key[0]
        maxlength = int(key[2])
        num = item['num']
        source = item['sub-source']
        valid = item['valid']
        result = item['result']
        score = 0
        valid_str = ''
        for i in range(len(valid)):
            valid_str += ' ' + valid[i] +' '
        f1.write("\"asn\": " + str(asn) + ", \"prefix\": " + prefix +  ", \"maxLength\": " + str(maxlength) + ", \"score\": " + str(score) + ", \"num\": " + str(num) + ", \"source\": "+ source +", \"result\": "+ result + ", \"valid\": " + valid_str + "\n")
    f1.close()

def read_irr_result(data, filename):
    with open(filename, 'r') as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()  # 
        raw_data = line.replace('"', '').replace(',', '')
        # 
        try:
            prefix = raw_data.split('prefix: ')[1].split(' ')[0]
        except:
            continue
        asn = int(raw_data.split('asn: ')[1].split(' ')[0])
        num = int(raw_data.split('num: ')[1].split(' ')[0])
        source = raw_data.split('source: ')[1].split(' ')[0]
        result = raw_data.split('result: ')[1].split(' ')[0]
        valid_words = raw_data.split('valid: ')[1].split()
        maxlen = int(prefix.split('/')[1])
        key = (prefix, asn, maxlen)
        value = {
            'num': num,
            'source': source,
            'result': result,
            'valid': valid_words
        }
        data[key] = value
        # print(data)

def read_irr_valid(data, filename):
    with open(filename, 'r') as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()  # 

        # 
        asn_start = line.find('"asn":') + len('"asn":')
        asn_end = line.find(',', asn_start)
        asn = int(line[asn_start:asn_end].strip())

        prefix_start = line.find('"prefix":') + len('"prefix":')
        prefix_end = line.find(',', prefix_start)
        prefix = line[prefix_start:prefix_end].strip()

        maxlen = int(prefix.split('/')[1])

        num_start = line.find('"num":') + len('"num":')
        num_end = line.find(',', num_start)
        num = int(line[num_start:num_end].strip())

        source_start = line.find('"source":') + len('"source":')
        source_end = line.find(',', source_start)
        source = line[source_start:source_end].strip()

        result_start = line.find('"result":') + len('"result":')
        result_end = line.find(',', result_start)
        result = line[result_start:result_end].strip()

        valid_start = line.find('"valid":') + len('"valid":')
        valid_end = line.rfind(']')
        valid_str = line[valid_start:valid_end].strip()

        #  "valid" 
        valid = []

        # 
        key = (prefix, asn, maxlen)
        value = {
            'num': num,
            'source': source,
            'result': result,
            'valid': valid
        }
        data[key] = value

def process_roa_valid_file(f, data, spemap_v4, spemap_v6, data_bgp):
    f1 = open(f, 'r', encoding = "ISO-8859-1")
    for line in f1:
        data_roa = json.loads(line)
        prefix = data_roa['roaip']
        asn = int(data_roa['roaasn'])
        maxlen = int(data_roa['roamaxlen'])
        bgpasn = int(data_roa['bgpasn'])
        bgpip = data_roa['bgpip']
        mode = data_roa['modebythisbgp']
        if mode == 'invalid':
            if data_bgp[(bgpip, bgpasn)]['result'] == 'valid':
                mode = 'invalid-valid'
            elif data_bgp[(bgpip, bgpasn)]['result'] == 'invalid':
                 mode = 'invalid-invalid'
        '''
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
        '''
        if (prefix, asn, maxlen) not in data:
            data[(prefix, asn, maxlen)] = {}
            data[(prefix, asn, maxlen)]['num'] = 1
            data[(prefix, asn, maxlen)]['source'] = 'ROA'
            data[(prefix, asn, maxlen)]['valid'] = []
            data[(prefix, asn, maxlen)]['result'] = mode
        else:
            if data[(prefix, asn, maxlen)]['result'] == 'invalid-valid' and mode == 'valid':
                data[(prefix, asn, maxlen)]['result'] = 'valid'
            elif data[(prefix, asn, maxlen)]['result'] == 'invalid-invalid' and mode == 'valid':
                data[(prefix, asn, maxlen)]['result'] = 'valid'
            elif data[(prefix, asn, maxlen)]['result'] == 'invalid-valid' and mode == 'invalid-invalid':
                data[(prefix, asn, maxlen)]['result'] = 'invalid-invalid'
            elif mode == 'valid':
                data[(prefix, asn, maxlen)]['result'] = 'valid'
            data[(prefix, asn, maxlen)]['num'] += 1
    f1.close()

def calculate_date(date_to_process, check_day):
    date_object = datetime.strptime(date_to_process, '%Y-%m-%d')
    bgpdate = []
    #  check_day 
    for i in range(check_day-1, -1, -1):
        result_date = date_object - timedelta(days=i)
        bgpdate.append(result_date.strftime('%Y-%m-%d'))
    print(bgpdate)
    return bgpdate

if __name__ == '__main__':
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
        log.write(f"{start_timetamp} roa filter started\n")
    # step 0
    # get args and prepare some file path
    
    if not os.path.exists(current_directory):
        os.makedirs(current_directory)
        #print("Date", current_directory, "doesn't exist, so there is no roa information for this day, exit(0)")
        #sys.exit(1)
    source_path = f'/home/demo/multi_source_data/{current_directory}/roa_data'
    output_path = f'{current_directory}/roa_data'
    trash_middle_data_path = output_path + '/trash_middle_data'
    bgpdate_list= calculate_date(date_to_process, check_day)
    if not os.path.exists(trash_middle_data_path):
        os.makedirs(trash_middle_data_path)
    print("Begin to work~!")
    data_roa_all = {}
    
    # step 1
    # prepare process data: build files in source/bgproute, irrraw, irrres and irrresaddunknow
    # note! process_data also have bgpdate_list, as example, ['2023-11-15', '2023-11-16']
    # step 1.1: for spemap, spemap_v4[length][ip_bits] has ['prefix'](list 1.0.0.0/24) and ['asns'](list 0)
    spemap_v4 = {}
    spemap_v6 = {}
    getspemap(spemap_v4, spemap_v6, private_ip_list_v4, private_ip_list_v6)
    # step 1.2: some worng bgproute information build from 'bgproute/exception' to dict bgp_exception
    bgp_exception = {}
    #process_bgp_exception('bgproute/exception', bgp_exception)
    # step 1.3: process irr data
    # build data_irr: data[(prefix, asn, maxlen)]['num'] = nums, data[(prefix, asn, maxlen)]['valid'] = []..., prefix == '0.0.0.0/0'
    data_roa_all = {}
    process_roa(source_path + '/' + date_to_process + '-0000', data_roa_all, spemap_v4, spemap_v6)
    if not os.path.exists(output_path + '/roaraw'):
        os.makedirs(output_path + '/roaraw')
    # step 1.4: process bgp data and check irr mode
    # step 1.4.1: build data_bgp that: data[(prefix, asn)]['num'] = nums, data[(prefix, asn)]['valid'] = []..., prefix='0.0.0.0/0'
    day_num = 0
    for date_temp in bgpdate_list:
        print("                                                                        ", end = "\r")
        print("Now, Step 1, Proparing bgp and roa info for date:", date_temp, end = "\r")
        year, month, day = map(str, date_temp.split('-'))
        timestamp = year+month+day
        data_bgp = {}
        data_roa_result = {}
        bgp_file = f'/home/demo/multi_source_data/{date_temp}/bgp_route/checklog/total/total-json-{timestamp}.json'   #zj temp
        if os.path.exists(bgp_file):
            process_bgp(bgp_file, data_bgp, spemap_v4, spemap_v6, bgp_exception)   #zj temp
            day_num += 1
        results_v4, results_v6, invalid, results = rov(data_bgp, data_roa_all, output_path + f'/roaraw/roavalidbybgpraw.{timestamp}')
        
        if os.path.exists(bgp_file):
            process_roa_valid_file(output_path + f'/roaraw/roavalidbybgpraw.{timestamp}', data_roa_result, spemap_v4, spemap_v6, data_bgp)
        for key in data_roa_all:
            if key not in data_roa_result:
                data_roa_all[key]['valid'].append('unknown')
            else:
                data_roa_all[key]['valid'].append(data_roa_result[key]['result'])
        
    
    # step 1.5: process score for every irr info and write down
    
    write_roa(data_roa_all, trash_middle_data_path + f'/data_roa_all.{timestamp}', day_num)    
    print("                                                                        ", end = "\r")
    print("Step 1 finished")
    
    # step 2
    # porcess data by days to get stable irr information
    print("                                                                        ", end = "\r")
    print("Now, Step 2, Getting stable roa information", end = "\r")
    data_roa = data_roa_all
    # if needed, data_irr = {} and read from next sentence
    # read_irr_result(data_irr, trash_middle_data_path + '/finallirrresult/result')
    # value_names = ['valid', 'match', 'invalid', 'notmatch', 'unknown', 'valid_and_irr_match', 'valid_and_unknown']
    '''
    data_roa = {} 
    year, month, day = map(str, current_directory.split('-'))
    timestamp = year+month+day
    read_irr_result(data_roa, trash_middle_data_path + f'/data_roa_all.{timestamp}')
    '''
    value_names = ['valid', 'invalid-invalid', 'invalid-valid', 'unknown', 'other', 'moas']
    stable_roa = {}
    for name in value_names:
        stable_roa[name] = []
    for key in data_roa:
        unique_values = set(data_roa[key]['valid'])

        # type-1 continue appearing
        '''
        if len(unique_values) == 1 and list(unique_values)[0] in value_names:
            stable_roa[list(unique_values)[0]].append(key)
        else:
            stable_roa['other'].append(key)
        '''

        #type-2 just appear
        '''
        if 'valid' in unique_values:
            stable_roa['valid'].append(key)
        elif 'invalid-invalid' in unique_values:
            stable_roa['invalid-invalid'].append(key)
        elif 'invalid-valid' in unique_values:
            stable_roa['invalid-valid'].append(key)
        else:
            stable_roa['unknown'].append(key)
        '''

        #type-3 just complementary
        flag_num = 0
        if key[1] == 0:
            stable_roa['valid'].append(key)
        elif data_roa[key]['valid'][-1] == 'valid':
            stable_roa['valid'].append(key)
        elif data_roa[key]['valid'][-1] == 'invalid-invalid':
            valid_num = data_roa[key]['valid'].count('valid')
            invalid_num = data_roa[key]['valid'].count('invalid-invalid')
            if valid_num > invalid_num:
                stable_roa['valid'].append(key)
            else:
                if valid_num > 0:
                    stable_roa['moas'].append(key)
                else:
                    stable_roa['invalid-invalid'].append(key)
        elif data_roa[key]['valid'][-1] == 'invalid-valid':
            if 'valid' in data_roa[key]['valid']:
                stable_roa['valid'].append(key)
            elif 'invalid-invalid' in data_roa[key]['valid']:
                stable_roa['invalid-invalid'].append(key)
            else:
                stable_roa['invalid-valid'].append(key)
        else:
            if 'valid' in data_roa[key]['valid']:
                stable_roa['valid'].append(key)
            elif 'invalid-invalid' in data_roa[key]['valid']:
                stable_roa['invalid-invalid'].append(key)
            elif 'invalid-valid' in data_roa[key]['valid']:
                stable_roa['invalid-valid'].append(key)
            else:
                stable_roa['unknown'].append(key)
    print(len(data_roa), flag_num)
    if not os.path.exists(trash_middle_data_path + '/stableroa'):
        os.makedirs(trash_middle_data_path + '/stableroa')
    filepath = trash_middle_data_path + '/stableroa/'
    for key in value_names:
        print(key, len(stable_roa[key]), len(stable_roa[key]) * 100 /len(data_roa) )
        with open(filepath + key, 'w') as file:
            for item in stable_roa[key]:
                formatted_item = str(item[1]) + ' ' + str(item[0])  + ' ' + str(item[2])+ ' ' + data_roa_all[item]['sub-source']
                file.write(formatted_item + '\n')
    #print(stable_roa['other'])
    '''
    if not os.path.exists(trash_middle_data_path + '/stableroa'):
        os.makedirs(trash_middle_data_path + '/stableroa')
    filepath = trash_middle_data_path + '/stableirr/'
    for name in value_names:
        with open(filepath+name, 'w') as file:
            for item in stable_irr[name]:
                formatted_item = str(item[1]) + ' ' + str(item[0].split('\n')[0]) + ' ' + data_irr_all[item]['sub-source']
                file.write(formatted_item + '\n')
    print("                                                                        ", end = "\r")
    print("Finished with no error")
    
    end_time = time.time()
    run_time = end_time - start_time
    print("：", run_time, "")

    total_num = len(stable_irr['valid']) + len(stable_irr['valid_and_unknown']) + len(stable_irr['valid_match_unknown'])
    '''
    total_num = len(stable_roa['valid']) + len(stable_roa['moas'])
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        duration = finish_time - starttime
        log.write(f"{finish_timestamp} roa filter ended, used {duration}\n")
        log.write("roa filter used " + str(check_day) + " days date, added " + str(total_num) + " roa records.\n")