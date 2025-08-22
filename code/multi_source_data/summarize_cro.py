import os
import sys
import copy
import netaddr
import ipaddress
from datetime import datetime, timedelta
current_directory = sys.argv[1]
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

def checkspeasn(asns):
    try:
        asn = int(list(asns)[0])
    except:
        asn = int(asns)
    #if asn == 0 or 64496 <= asn <= 131071 or 401309 <= asn <= 4294967295 or asn == 23456 or 153914 <= asn <= 196607 or 216476 <= asn <= 262143 or 274845 <= asn <= 327679 or 329728 <= asn <= 393215:
    if 64496 <= asn <= 131071 or 401309 <= asn <= 4294967295 or asn == 23456 or 153914 <= asn <= 196607 or 216476 <= asn <= 262143 or 274845 <= asn <= 327679 or 329728 <= asn <= 393215:
        return True
    else:
        return False

def write_cro(data, cro_file):
    f1 = open(cro_file, 'w')
    f1.write("{\n")
    f1.write("\"metadata\": {\n")
    f1.write("\"generated\": " + str(len(data)) + ",\n")
    f1.write("\"generatedTime\": \"" + str(datetime.now()) + "\"\n")
    f1.write("},\n")
    f1.write("\"roas\": [\n")
    total_num = len(data)
    num = 1
    for key, item in data.items():
        ty_pe = ''
        for i in range(len(item['type'])):
            if i < len(item['type']) - 1:
                ty_pe += item['type'][i] + ', '
            else:
                ty_pe += item['type'][i]
        
        tal = ''
        for i in range(len(item['tal'])):
            if i < len(item['tal']) - 1:
                tal += item['tal'][i] + ', '
            else:
                tal += item['tal'][i]
            
        if num < total_num:
            f1.write("{ \"asn\": \"AS" + str(key[1]) + "\", \"prefix\": \"" + key[0] + "\", \"maxLength\": " + str(key[2]) +", \"source\": [ { \"type\": \"" + ty_pe + "\", \"uri\": \"" + item['uri'] + "\", \"tal\": \"" + tal + "\", \"validity\": { \"notBefore\": \"" + item['time'][0] + "\", \"notAfter\": \"" + item['time'][1] + "\" }, \"chainValidity\": { \"notBefore\": \"" + item['time'][2] + "\", \"notAfter\": \"" + item['time'][3] + "\" } }] },\n")
            num += 1
        else:
            f1.write("{ \"asn\": \"AS" + str(key[1]) + "\", \"prefix\": \"" + key[0] + "\", \"maxLength\": " + str(key[2]) +", \"source\": [ { \"type\": \"" + ty_pe + "\", \"uri\": \"" + item['uri'] + "\", \"tal\": \"" + tal + "\", \"validity\": { \"notBefore\": \"" + item['time'][0] + "\", \"notAfter\": \"" + item['time'][1] + "\" }, \"chainValidity\": { \"notBefore\": \"" + item['time'][2] + "\", \"notAfter\": \"" + item['time'][3] + "\" } }] }\n")
    f1.write("]}\n")

def process_roa(f, data):
    f1 = open(f, 'r')
    for line in f1:
        asn = int(line.split(' ')[0])
        prefix = line.split(' ')[1]
        maxLength = int(line.split(' ')[2])
        source = line.split(' ')[3].split('\n')[0]
        if (prefix, asn, maxLength) not in data:
            data[(prefix, asn, maxLength)] = {}
            data[(prefix, asn, maxLength)] = {}
            data[(prefix, asn, maxLength)]['num'] = 1
            data[(prefix, asn, maxLength)]['time'] = ['','','','']
            data[(prefix, asn, maxLength)]['type'] = ['ROA']
            data[(prefix, asn, maxLength)]['uri'] = ''
            data[(prefix, asn, maxLength)]['tal'] = ['ROA-' + source]
        else:
            data[(prefix, asn, maxLength)]['num'] = +1
            data[(prefix, asn, maxLength)]['type'].append('ROA')
            data[(prefix, asn, maxLength)]['tal'].append('ROA-' + source)

def roa_aggregate(data_asn, data):
    #process aggregate
    for key in data_asn:
        for maxlen in data_asn[key]:
            networks = []
            temp_list = copy.deepcopy(data_asn[key][maxlen])
            for prefix in data_asn[key][maxlen]:
                #prefix = temp[0]
                #network = ipaddress.IPv4Network(prefix, strict=False)
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
                    if (prefix, asn, maxLength) not in data:
                        data[(prefix, asn, maxLength)] = {}
                        data[(prefix, asn, maxLength)]['num'] = 1
                        data[(prefix, asn, maxLength)]['time'] = ['','','','']
                        data[(prefix, asn, maxLength)]['type'] = ['roa_aggregate']
                        data[(prefix, asn, maxLength)]['uri'] = ''
                        data[(prefix, asn, maxLength)]['tal'] = []
                    else:
                        data[(prefix, asn, maxLength)]['num'] = +1
                        data[(prefix, asn, maxLength)]['type'].append('roa_aggregate')
                        

def process_bgp_roa_new(f, data, flag='BGP'):
    f1 = open(f, 'r')
    for line in f1:
        try:
            asn = int(line.split(' ')[0])
            prefix = line.split(' ')[1]
            maxLength = int(line.split(' ')[2].split('\n')[0])
        except:
            continue
        if (prefix, asn, maxLength) not in data:
            data[(prefix, asn, maxLength)] = {}
            data[(prefix, asn, maxLength)] = {}
            data[(prefix, asn, maxLength)]['num'] = 1
            data[(prefix, asn, maxLength)]['time'] = ['','','','']
            data[(prefix, asn, maxLength)]['type'] = [flag]
            data[(prefix, asn, maxLength)]['uri'] = ''
            data[(prefix, asn, maxLength)]['tal'] = []
        else:
            data[(prefix, asn, maxLength)]['num'] = +1
            data[(prefix, asn, maxLength)]['type'].append(flag)

def process_irr(f, data):
    f1 = open(f, 'r')
    for line in f1:
        asn = int(line.split(' ')[0])
        prefix = line.split(' ')[1]
        maxLength = int(prefix.split('/')[1])
        source = line.split(' ')[2].split('\n')[0]
        if (prefix, asn, maxLength) not in data:
            data[(prefix, asn, maxLength)] = {}
            data[(prefix, asn, maxLength)] = {}
            data[(prefix, asn, maxLength)]['num'] = 1
            data[(prefix, asn, maxLength)]['time'] = ['','','','']
            data[(prefix, asn, maxLength)]['type'] = ['IRR']
            data[(prefix, asn, maxLength)]['uri'] = ''
            data[(prefix, asn, maxLength)]['tal'] = ['IRR-' + source]
        else:
            data[(prefix, asn, maxLength)]['num'] = +1
            data[(prefix, asn, maxLength)]['type'].append('IRR')
            data[(prefix, asn, maxLength)]['tal'].append('IRR-' + source)

def main():
    
    start_time = datetime.now()
    start_timetamp = start_time.strftime("%Y%m%d %H:%M:%S")
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        log.write(f"{start_timetamp} generate cro started\n")

    cro_file = current_directory + "/cro_data/cro_" + current_directory
    cro_retification_file = current_directory + "/cro_data/cro_retification_" + current_directory
    
    year, month, day = map(str, current_directory.split('-'))

    data_cro = {}

    spemap_v4 = {}
    spemap_v6 = {}
    getspemap(spemap_v4, spemap_v6, private_ip_list_v4, private_ip_list_v6)

    #step1: process roa
    print("process roa")
    valid_roa_file = current_directory + "/roa_data/trash_middle_data/stableroa/valid"
    process_roa(valid_roa_file, data_cro)
    valid_roa_file = current_directory + "/roa_data/trash_middle_data/stableroa/moas"
    process_roa(valid_roa_file, data_cro)
    valid_roa_file = current_directory + "/roa_data/trash_middle_data/stableroa/unknown"
    process_roa(valid_roa_file, data_cro)
    


    #step2: read irr
    print("process irr")
    valid_irr_file = current_directory + "/irr_data/trash_middle_data/stableirr/valid"
    process_irr(valid_irr_file, data_cro)
    #valid_irr_file = current_directory + "/irr_data/trash_middle_data/stableirr/moas"
    #process_irr(valid_irr_file, data_cro)

    #step3: read bgp
    print("process bgp")
    data_cro_default = copy.deepcopy(data_cro)
    bgp_file = '/home/demo/multi_source_data/' + current_directory + "/bgp_filter_data/bgp_frequent"
    process_bgp_roa_new(bgp_file, data_cro_default, flag='BGP')
    write_cro(data_cro_default, cro_file)
    
    #local record
    data_cro_67 = copy.deepcopy(data_cro)
    bgp_file = '/home/demo/multi_source_data/' + current_directory + "/bgp_filter_data/bgp_frequent_67"
    if os.path.exists(bgp_file):
        process_bgp_roa_new(bgp_file, data_cro_67, flag='BGP')
        write_cro(data_cro_67, cro_file + "_67")

    
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        duration = finish_time - start_time
        log.write(f"{finish_timestamp} generate cro ended, generated {str(len(data_cro))} records, used {duration}\n")

    #step4: process invalid roa
    print("process invalid roa")
    valid_roa_file = current_directory + "/roa_data/trash_middle_data/stableroa/invalid-invalid"
    process_roa(valid_roa_file, data_cro_default)

    process_roa(valid_roa_file, data_cro_67)

    #step2: read irr
    print("process irr")
    #valid_irr_file = current_directory + "/irr_data/trash_middle_data/stableirr/invalid"
    #process_irr(valid_irr_file, data_cro)
    #valid_irr_file = current_directory + "/irr_data/trash_middle_data/stableirr/moas"
    #process_irr(valid_irr_file, data_cro)
    write_cro(data_cro_default, cro_retification_file)
    write_cro(data_cro_67, cro_retification_file + "_67")



    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        duration = finish_time - start_time
        log.write(f"{finish_timestamp} generate cro_retification ended, generated total {str(len(data_cro))} records, used {duration}\n")

if __name__ == '__main__':
    main()
