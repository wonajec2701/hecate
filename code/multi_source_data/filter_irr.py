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
        if len(key) == 3:
            maxlen = [key[2], key[2]]
        elif len(key) == 2:
            maxlen = [128, 32]
        """ for IPv6 ROA """
        if ':' in pfx:
            createROAmap(roamap_v6, asn, pfx, maxlen[0])
        else:
            createROAmap(roamap_v4, asn, pfx, maxlen[1])

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

def process_bgp_cad(file, data, spemap_v4, spemap_v6, bgp_exception):
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
        else:
            data[(prefix, asn)]['num'] += 1

    for key, item in bgp_exception.items():
        if key in data:
            data.pop(key)

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

def process_irr(f, data, spemap_v4, spemap_v6):
    f1 = open(f, 'r', encoding = "ISO-8859-1")
    for line in f1:
        try:
            prefix = line.split(' ')[1]
        except:
            print(line)
            continue
        try:
            asn = int(line.split(' ')[0])
        except:
            print(line)
            continue
        try:
            source = line.split(' ')[2].split('\n')[0]
        except:
            source = 'None'
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
        if (prefix, asn, maxlen) not in data:
            data[(prefix, asn, maxlen)] = {}
            data[(prefix, asn, maxlen)]['num'] = 1
            data[(prefix, asn, maxlen)]['source'] = 'IRR'
            data[(prefix, asn, maxlen)]['sub-source'] = source
            data[(prefix, asn, maxlen)]['valid'] = []
            data[(prefix, asn, maxlen)]['result'] = 'unknown'
        else:
            data[(prefix, asn, maxlen)]['num'] += 1
    f1.close()


""" route orgin validation based on ROAs """
def rovproc(roamap, pfx, length, asnset, pfxstr, data_bgp, data_roa):
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
                    data_roa[(v['vrp'], asn, maxlen)]['valid'].append([pfxstr, asn])
                elif length <= maxlen:
                    data_bgp[(pfxstr, asnset)]['invalid'].append([v['vrp'], asn, maxlen, data_roa[(v['vrp'], asn, maxlen)]['source']])
                    data_roa[(v['vrp'], asn, maxlen)]['invalid'].append([pfxstr, asnset])
                else:
                    data_bgp[(pfxstr, asnset)]['invalid'].append([v['vrp'], asn, maxlen, data_roa[(v['vrp'], asn, maxlen)]['source']])
                    data_roa[(v['vrp'], asn, maxlen)]['invalid'].append([pfxstr, asnset])
                    #return r

    if pfx_exists and r!= 'valid':
        r = 'invalid'

    return r

def rovproc2(roamap, pfx, length, asnset, pfxstr, data_bgp, data_irr, filenamebybgpdate):
    # dict roamap_v4[length][ip_bits] has ['num'](int) and ['vrps'](dict)
    #   dict roamap_v4[length][ip_bits]['vrps'][0, 1, ...] has ['vrp']('1.0.0.0/24'), ['asn'](int), ['maxlen'](int), ['num'](int)
    # pfx is ip bits(bgp)
    # length is ip bits length(bgp)
    # asnset is int, asnumber(bgp)
    # pfxstr is '1.0.0.0/24' string(bgp)
    # data_bgp is data[(prefix, asn)]['num'] = nums, data[(prefix, asn)]['valid'] = []..., prefix='0.0.0.0/0'
    # data_irr is data[(prefix, asn, maxlen)]['num'] = nums, data[(prefix, asn, maxlen)]['valid'] = []..., prefix == '0.0.0.0/0'
    r = 'unknown'
    pfx_exists = False
    for pl in range(length, -1, -1):
        # length is route ip length, so irr length <= length
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
                    # valid, irr length == bgp length, asn match
                    #r = "%s %s %s %s" % ('valid ', v['vrp'], maxlen, asn)
                    r = 'valid'
                    #print((v, asn, maxlen))
                    # data_irr[(v['vrp'], asn, maxlen)]['valid'].append([pfxstr, asn, 'valid'])
                    # data_irr[(v['vrp'], asn, maxlen)]['result'] = 'valid' 
                    data_line = {
                        "irrasn": asn,
                        "irrip": v['vrp'],
                        "bgpasn": asnset,
                        "bgpip": pfxstr,
                        "modebythisbgp": r
                    }
                    write_data_to_file(data_line, filenamebybgpdate)
                elif pl < length and asn == asnset:
                    r = 'match'
                    # data_irr[(v['vrp'], asn, maxlen)]['valid'].append([pfxstr, asn, 'match'])
                    # if data_irr[(v['vrp'], asn, maxlen)]['result'] != 'valid' and data_irr[(v['vrp'], asn, maxlen)]['result'] != 'invalid':
                    #     data_irr[(v['vrp'], asn, maxlen)]['result'] = 'match'
                    data_line = {
                        "irrasn": asn,
                        "irrip": v['vrp'],
                        "bgpasn": asnset,
                        "bgpip": pfxstr,
                        "modebythisbgp": r
                    }
                    write_data_to_file(data_line, filenamebybgpdate)
                elif pl == length and asn != asnset:
                    r = 'invalid'
                    # data_irr[(v['vrp'], asn, maxlen)]['valid'].append([pfxstr, asn, 'invalid'])
                    # if data_irr[(v['vrp'], asn, maxlen)]['result'] != 'valid':
                    #     data_irr[(v['vrp'], asn, maxlen)]['result'] = 'invalid'
                    data_line = {
                        "irrasn": asn,
                        "irrip": v['vrp'],
                        "bgpasn": asnset,
                        "bgpip": pfxstr,
                        "modebythisbgp": r
                    }
                    write_data_to_file(data_line, filenamebybgpdate)
                elif pl != length and asn != asnset:
                    r = 'notmatch'
                    # data_irr[(v['vrp'], asn, maxlen)]['valid'].append([pfxstr, asn, 'notmatch'])
                    # if data_irr[(v['vrp'], asn, maxlen)]['result'] == 'unknown':
                    #     data_irr[(v['vrp'], asn, maxlen)]['result'] = 'notmatch'
                    data_line = {
                        "irrasn": asn,
                        "irrip": v['vrp'],
                        "bgpasn": asnset,
                        "bgpip": pfxstr,
                        "modebythisbgp": r
                    }
                    write_data_to_file(data_line, filenamebybgpdate)
                else :
                    r = 'unknown'

    if pfx_exists and r!= 'valid':
        r = 'invalid'

    return r

def rov(data_bgp, data_irr, filenamebybgpdate = None):
    print(filenamebybgpdate, '123')
    f = open(filenamebybgpdate, 'w')
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
    getirrmap(irrmap_v4, irrmap_v6, data_irr)
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
                if filenamebybgpdate is None:
                    r_irr = rovproc(irrmap_v6, pfx, pl, asns, pfxstr, data_bgp, data_irr)
                else:
                    r_irr = rovproc2(irrmap_v6, pfx, pl, asns, pfxstr, data_bgp, data_irr, filenamebybgpdate)
                # check every irr data for this bgp data
                results_v6[results.index(r_irr)] += 1
                if r_irr == 'invalid':
                    invalid[(pfxstr, asn)] = data_bgp[(pfxstr, asn)]['invalid']
                results_t[(pfxstr, asn)] = r_irr
    

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
                if filenamebybgpdate is None:
                    r_irr = rovproc(irrmap_v4, pfx, pl, asns, pfxstr, data_bgp, data_irr)
                else:
                    r_irr = rovproc2(irrmap_v4, pfx, pl, asns, pfxstr, data_bgp, data_irr, filenamebybgpdate)
                results_v4[results.index(r_irr)] += 1
                if r_irr == 'invalid':
                    invalid[(pfxstr, asn)] = data_bgp[(pfxstr, asn)]['invalid']
                results_t[(pfxstr, asn)] = r_irr
    return results_v4, results_v6, invalid, results_t


def write_irr(data, new_f, day_num):
    f1 = open(new_f, 'w')
    f1.write(str(day_num) + '\n')
    for key, item in data.items():
        asn = key[1]
        prefix = key[0]
        num = item['num']
        source = item['sub-source']
        valid = item['valid']
        result = item['result']
        score = item['score']
        valid_str = ''
        for i in range(len(valid)):
            valid_str += ' ' + valid[i] +' '
        f1.write("\"asn\": " + str(asn) + ", \"prefix\": " + prefix + ", \"score\": " + str(score) + ", \"num\": " + str(num) + ", \"source\": "+ str(source) +", \"result\": "+ result + ", \"valid\": " + valid_str + "\n")
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

def process_irr_valid_file(f, data, spemap_v4, spemap_v6):
    f1 = open(f, 'r', encoding = "ISO-8859-1")
    for line in f1:
        try:
            data_irr = json.loads(line)
        except:
            print(line)
        prefix = data_irr['irrip']
        asn = int(data_irr['irrasn'])
        mode = data_irr['modebythisbgp']
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
        maxlen = int(prefix.split('/')[1].split('\n')[0])
        if (prefix, asn, maxlen) not in data:
            data[(prefix, asn, maxlen)] = {}
            data[(prefix, asn, maxlen)]['num'] = 1
            data[(prefix, asn, maxlen)]['source'] = 'IRR'
            data[(prefix, asn, maxlen)]['valid'] = []
            data[(prefix, asn, maxlen)]['result'] = mode
        else:
            if data[(prefix, asn, maxlen)]['result'] == 'notmatch' and mode == 'match':
                data[(prefix, asn, maxlen)]['result'] = 'match'
            elif (data[(prefix, asn, maxlen)]['result'] == 'notmatch' or data[(prefix, asn, maxlen)]['result'] == 'match') and mode == 'invalid':
                data[(prefix, asn, maxlen)]['result'] = 'invalid'
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
        log.write(f"{start_timetamp} irr filter started\n")
    # step 0
    # get args and prepare some file path
    
    if not os.path.exists(current_directory):
        os.makedirs(current_directory)
        #print("Date", current_directory, "doesn't exist, so there is no irr information for this day, exit(0)")
        #sys.exit(1)
    source_path = f'/home/demo/multi_source_data/{current_directory}/irr_data'
    output_path = f'{current_directory}/irr_data'
    trash_middle_data_path = output_path + '/trash_middle_data'
    bgpdate_list= calculate_date(date_to_process, check_day)
    if not os.path.exists(trash_middle_data_path):
        os.makedirs(trash_middle_data_path)
    print("Begin to work~!")
    
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
    data_irr_all = {}
    process_irr(source_path + f'/irr-route-total-{date_to_process}', data_irr_all, spemap_v4, spemap_v6)
    process_irr(source_path + f'/irr-route6-total-{date_to_process}', data_irr_all, spemap_v4, spemap_v6)
    if not os.path.exists(output_path + '/irrraw'):
        os.makedirs(output_path + '/irrraw')
    # step 1.4: process bgp data and check irr mode
    # step 1.4.1: build data_bgp that: data[(prefix, asn)]['num'] = nums, data[(prefix, asn)]['valid'] = []..., prefix='0.0.0.0/0'
    day_num = 0
    for date_temp in bgpdate_list:
        print("                                                                        ", end = "\r")
        print("Now, Step 1, Proparing bgp and irr info for date:", date_temp, end = "\r")
        year, month, day = map(str, date_temp.split('-'))
        timestamp = year+month+day
        data_bgp = {}
        data_irr_result = {}
        bgp_file = f'/home/demo/multi_source_data/{date_temp}/bgp_route/checklog/total/total-json-{timestamp}.json'   #zj temp
        if os.path.exists(bgp_file):
            process_bgp(bgp_file, data_bgp, spemap_v4, spemap_v6, bgp_exception)   #zj temp
            #process_bgp_cad(bgp_file, data_bgp, spemap_v4, spemap_v6, bgp_exception)
            day_num += 1
            # else, data_bgp = {} and every irr is unknown
            # irrvalidbybgpraw.2023{i} is a very long file, an irr information will appear many times if it valid/invalid...... every bgp information
            # irrvalidbybgpresult.2023{i} is a shorter file, an irr information will appear less than one time: if irr is unknown, it will not appear
        results_v4, results_v6, invalid, results = rov(data_bgp, data_irr_all, output_path + f'/irrraw/irrvalidbybgpraw.{timestamp}')
        if os.path.exists(bgp_file):
            process_irr_valid_file(output_path + f'/irrraw/irrvalidbybgpraw.{timestamp}', data_irr_result, spemap_v4, spemap_v6)
        # as score is added, this sentence should not be used!! 
        # write_irr(data_irr_result, trash_middle_data_path + f'/irrres/irrvalidbybgpresult.{timestamp}')
        for key in data_irr_all:
            if key not in data_irr_result:
                data_irr_all[key]['valid'].append('unknown')
            else:
                data_irr_all[key]['valid'].append(data_irr_result[key]['result'])
    # step 1.5: process score for every irr info and write down
    data_irr = data_irr_all
    for key in data_irr:
        score = 0
        # print(data_irr[key])
        for mode in data_irr[key]['valid']:
            # print(mode)
            if mode == 'valid':
                score = score + 100
            elif mode == 'invalid':
                score = score - 100
            elif mode == 'match':
                score = score + 80
            elif mode == 'notmatch':
                score = score - 80
            elif mode == 'unknown':
                score = score + 0
            else:
                print("Wrong!!")
        # print(score)
        data_irr[key]['score'] = score
    write_irr(data_irr_all, trash_middle_data_path + f'/data_irr_all.{timestamp}', day_num)    
    print("                                                                        ", end = "\r")
    print("Step 1 finished")
    
    # step 2
    # porcess data by days to get stable irr information
    print("                                                                        ", end = "\r")
    print("Now, Step 2, Getting stable irr information", end = "\r")
    data_irr = data_irr_all
    '''
    data_irr = {} 
    year, month, day = map(str, current_directory.split('-'))
    timestamp = year+month+day
    read_irr_result(data_irr, trash_middle_data_path + f'/data_irr_all.{timestamp}')
    # if needed, data_irr = {} and read from next sentence
    # read_irr_result(data_irr, trash_middle_data_path + '/finallirrresult/result')
    # value_names = ['valid', 'match', 'invalid', 'notmatch', 'unknown', 'valid_and_irr_match', 'valid_and_unknown']
    '''
    value_names = ['valid', 'invalid', 'match', 'notmatch', 'unknown', 'other', 'moas']
    stable_irr = {}
    for name in value_names:
        stable_irr[name] = []
    num_other_unknown = 0
    for key in data_irr:
        unique_values = set(data_irr[key]['valid'])
        #type-0 initial+moas
        if 'valid' in unique_values and 'invalid' in unique_values:
            stable_irr['moas'].append(key)
        elif len(unique_values) == 1 and 'valid' in unique_values:
            stable_irr['valid'].append(key)
        elif len(unique_values) == 2 and 'valid' in unique_values and 'unknown' in unique_values:
            stable_irr['valid'].append(key)
        elif len(unique_values) == 3 and 'valid' in unique_values and 'unknown' in unique_values and 'match' in unique_values:
            stable_irr['valid'].append(key)
        elif 'invalid' in unique_values:
            stable_irr['invalid'].append(key)
        else:
            stable_irr['unknown'].append(key)

        #type-1 initial
        '''
        if len(unique_values) == 1 and list(unique_values)[0] in value_names:
            stable_irr[list(unique_values)[0]].append(key)
        elif len(unique_values) == 2 and 'valid' in unique_values and 'unknown' in unique_values:
            stable_irr['valid_and_unknown'].append(key)
        elif len(unique_values) == 3 and 'valid' in unique_values and 'unknown' in unique_values and 'match' in unique_values:
            stable_irr['valid_match_unknown'].append(key)
        '''
        '''
        #type-2 try
        if 'valid' in unique_values and 'invalid' in unique_values:
            stable_irr['moas'].append(key)
        elif 'valid' in unique_values and data_irr[key]['valid'].count('valid') >= len(data_irr[key]['valid']) / 2:
            stable_irr['valid'].append(key)
        elif 'valid' in unique_values and data_irr[key]['valid'].count('valid') < len(data_irr[key]['valid']) / 2:
            stable_irr['other'].append(key)
        elif 'invalid' in unique_values:
            stable_irr['invalid'].append(key)
        else:
            stable_irr['unknown'].append(key)
        '''
        #type-3 now
        '''
        if len(unique_values) == 1 and 'valid' in unique_values:
            stable_irr['valid'].append(key)
        elif len(unique_values) == 2 and 'valid' in unique_values and 'unknown' in unique_values:
            stable_irr['valid'].append(key)
        elif 'valid' in unique_values and 'invalid' in unique_values:
            stable_irr['moas'].append(key)
        elif 'valid' in unique_values and data_irr[key]['valid'].count('valid') >= len(data_irr[key]['valid']) / 2:
            stable_irr['valid'].append(key)
        elif len(unique_values) == 1 and 'invalid' in unique_values:
            stable_irr['invalid'].append(key)
        elif len(unique_values) == 2 and 'invalid' in unique_values and 'unknown' in unique_values:
            stable_irr['invalid'].append(key)
        elif 'invalid' in unique_values and data_irr[key]['valid'].count('invalid') >= len(data_irr[key]['valid']) / 2:
            stable_irr['invalid'].append(key)
        elif len(unique_values) == 1 and 'match' in unique_values:
            stable_irr['match'].append(key)
        elif len(unique_values) == 2 and 'match' in unique_values and 'unknown' in unique_values:
            stable_irr['match'].append(key)
        elif len(unique_values) == 1 and 'notmatch' in unique_values:
            stable_irr['notmatch'].append(key)
        elif len(unique_values) == 2 and 'notmatch' in unique_values and 'unknown' in unique_values:
            stable_irr['notmatch'].append(key)
        elif len(unique_values) == 1 and 'unknown' in unique_values:
            stable_irr['unknown'].append(key)
        else:
            if data_irr[key]['valid'][-1] == data_irr[key]['valid'][-2] == data_irr[key]['valid'][-3]:
                stable_irr[data_irr[key]['valid'][-1]].append(key)
            elif data_irr[key]['valid'].count('unknown') >= len(data_irr[key]['valid']) / 2:
                stable_irr['unknown'].append(key)
            elif len(unique_values) == 3 and 'match' in unique_values and 'notmatch' in unique_values and 'unknown' in unique_values:
                stable_irr['unknown'].append(key)
            elif 'valid' in unique_values and 'invalid' not in unique_values and 'match' in unique_values and 'notmatch' not in unique_values:
                stable_irr['valid'].append(key)
            elif 'valid' not in unique_values and 'invalid' in unique_values and 'notmatch' in unique_values:
                stable_irr['invalid'].append(key)
            else: 
                stable_irr['other'].append(key)
    minus_list = []
    for i in range(len(stable_irr['other']) - 1):
        for j in range(i+1, len(stable_irr['other'])):
            key1 = stable_irr['other'][i]
            key2 = stable_irr['other'][j]
            #print(key1, key2)
            if key1 != key2 and key1[0] == key2[0] and key1[1] != key2[1]:
                if key1 not in stable_irr['moas']:
                    stable_irr['moas'].append(key1)
                    minus_list.append(key1)
                if key2 not in stable_irr['moas']:
                    stable_irr['moas'].append(key2)
                    minus_list.append(key2)
    for key in minus_list:
        stable_irr['other'].remove(key)
    
    for key in stable_irr['other']:
        print(key)
    '''
    print(len(data_irr), num_other_unknown)
    if not os.path.exists(trash_middle_data_path + '/stableirr'):
        os.makedirs(trash_middle_data_path + '/stableirr')
    filepath = trash_middle_data_path + '/stableirr/'
    for key in value_names:
        print(key, len(stable_irr[key]), len(stable_irr[key]) * 100 /len(data_irr) )
        with open(filepath + key, 'w') as file:
            for item in stable_irr[key]:
                formatted_item = str(item[1]) + ' ' + str(item[0].split('\n')[0]) + ' ' + data_irr_all[item]['sub-source']
                file.write(formatted_item + '\n')
    '''
    if not os.path.exists(trash_middle_data_path + '/stableirr'):
        os.makedirs(trash_middle_data_path + '/stableirr')
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
    total_num = len(stable_irr['valid']) + len(stable_irr['moas'])
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        duration = finish_time - starttime
        log.write(f"{finish_timestamp} irr filter ended, used {duration}\n")
        log.write("irr filter used " + str(check_day) + " days date, added " + str(total_num) + " irr records.\n")
    