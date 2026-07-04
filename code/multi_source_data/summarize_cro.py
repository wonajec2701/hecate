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

def build_validation_map(data):
    roamap_v4 = {}
    roamap_v6 = {}
    for key in data:
        prefix = key[0]
        asn = int(key[1])
        maxLength = int(key[2])
        pfx = prefix.split('/')[0]
        pl = int(prefix.split('/')[1].split('\n')[0])
        if ':' in prefix:
            roamap = roamap_v6
        else:
            roamap = roamap_v4
        pfxbin = getpfxbin(pfx, pl)
        if pl not in roamap:
            roamap[pl] = {}
        if pfxbin not in roamap[pl]:
            roamap[pl][pfxbin] = {}
            roamap[pl][pfxbin]['num'] = 0
            roamap[pl][pfxbin]['vrps'] = []
        roamap[pl][pfxbin]['num'] += 1
        roamap[pl][pfxbin]['vrps'].append({'asn': asn, 'maxlen': maxLength})
    return roamap_v4, roamap_v6

def rovproc_single(roamap, pfx, length, asnset):
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
            for v in vrpset['vrps']:
                if length <= v['maxlen'] and v['asn'] == asnset:
                    r = 'valid'
                elif v['asn'] != asnset:
                    invalid_list.append('invalid_asn')
                else:
                    invalid_list.append('invalid_maxlen')

    if pfx_exists and r != 'valid':
        if 'invalid_asn' in invalid_list:
            r = 'invalid_asn'
        elif 'invalid_maxlen' in invalid_list:
            r = 'invalid_maxlen'
    return r

def rovproc_irr_single(roamap, pfx, length, asnset):
    r = 'unknown'
    invalid_list = []
    for pl in range(length, -1, -1):
        if pl not in roamap:
            continue
        t = pfx[:pl]
        if t in roamap[pl]:
            vrpset = roamap[pl][t]
            for v in vrpset['vrps']:
                asn = v['asn']
                if pl == length and asn == asnset:
                    invalid_list.append('valid')
                elif pl == length and asn != asnset:
                    invalid_list.append('invalid')
                elif pl < length and asn == asnset:
                    invalid_list.append('match')
                elif pl != length and asn != asnset:
                    invalid_list.append('notmatch')
                else:
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
    prefix = key[0]
    asn = int(key[1])
    pfx = prefix.split('/')[0]
    pfxlen = int(prefix.split('/')[1].split('\n')[0])
    pfxbin = getpfxbin(pfx, pfxlen)
    if ':' in prefix:
        if flag == 'irr':
            return rovproc_irr_single(roamap_v6, pfxbin, pfxlen, asn)
        return rovproc_single(roamap_v6, pfxbin, pfxlen, asn)
    if flag == 'irr':
        return rovproc_irr_single(roamap_v4, pfxbin, pfxlen, asn)
    return rovproc_single(roamap_v4, pfxbin, pfxlen, asn)

def is_roa_invalid(result):
    return result.startswith('invalid')

def is_irr_invalid(result):
    return result in ['invalid', 'notmatch']

def write_bgp_stability_alert(alert_file, prefix, asn, maxLength, roa_rov, irr_rov):
    with open(alert_file, 'a') as f:
        f.write(str(asn) + ' ' + prefix + ' ' + str(maxLength) + ' RPKI=' + roa_rov + ' IRR=' + irr_rov + '\n')

def roa_aggregate(data_asn, data):
    #process aggregate
    for key in data_asn:
        if int(key) == 0:
            continue
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
                        

def process_bgp_roa_new(f, data, flag='BGP', roa_maps=None, irr_maps=None, alert_file=None):
    f1 = open(f, 'r')
    for line in f1:
        try:
            asn = int(line.split(' ')[0])
            prefix = line.split(' ')[1]
            maxLength = int(line.split(' ')[2].split('\n')[0])
        except:
            continue
        if (prefix, asn, maxLength) not in data and roa_maps is not None and irr_maps is not None and alert_file is not None:
            roa_rov = rov_single((prefix, asn), roa_maps[0], roa_maps[1])
            irr_rov = rov_single((prefix, asn), irr_maps[0], irr_maps[1], 'irr')
            if is_roa_invalid(roa_rov) and is_irr_invalid(irr_rov):
                write_bgp_stability_alert(alert_file, prefix, asn, maxLength, roa_rov, irr_rov)
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
    data_roa = {}
    valid_roa_file = current_directory + "/roa_data/trash_middle_data/stableroa/valid"
    process_roa(valid_roa_file, data_cro)
    process_roa(valid_roa_file, data_roa)
    valid_roa_file = current_directory + "/roa_data/trash_middle_data/stableroa/moas"
    process_roa(valid_roa_file, data_cro)
    process_roa(valid_roa_file, data_roa)
    valid_roa_file = current_directory + "/roa_data/trash_middle_data/stableroa/unknown"
    process_roa(valid_roa_file, data_cro)
    process_roa(valid_roa_file, data_roa)
    invalid_roa_file = current_directory + "/roa_data/trash_middle_data/stableroa/invalid-invalid"
    if os.path.exists(invalid_roa_file):
        process_roa(invalid_roa_file, data_roa)
    


    #step2: read irr
    print("process irr")
    data_irr = {}
    valid_irr_file = current_directory + "/irr_data/trash_middle_data/stableirr/valid"
    process_irr(valid_irr_file, data_cro)
    process_irr(valid_irr_file, data_irr)
    #valid_irr_file = current_directory + "/irr_data/trash_middle_data/stableirr/moas"
    #process_irr(valid_irr_file, data_cro)
    roa_maps = build_validation_map(data_roa)
    irr_maps = build_validation_map(data_irr)

    #step3: read bgp
    print("process bgp")
    data_cro_default = copy.deepcopy(data_cro)
    bgp_file = '/home/demo/multi_source_data/' + current_directory + "/bgp_filter_data/bgp_frequent"
    open(current_directory + "/cro_data/alert_bgp_stability_conflict", 'w').close()
    process_bgp_roa_new(bgp_file, data_cro_default, flag='BGP', roa_maps=roa_maps, irr_maps=irr_maps, alert_file=current_directory + "/cro_data/alert_bgp_stability_conflict")
    write_cro(data_cro_default, cro_file)
    
    #local record
    data_cro_67 = copy.deepcopy(data_cro)
    bgp_file = '/home/demo/multi_source_data/' + current_directory + "/bgp_filter_data/bgp_frequent_67"
    if os.path.exists(bgp_file):
        open(current_directory + "/cro_data/alert_bgp_stability_conflict_67", 'w').close()
        process_bgp_roa_new(bgp_file, data_cro_67, flag='BGP', roa_maps=roa_maps, irr_maps=irr_maps, alert_file=current_directory + "/cro_data/alert_bgp_stability_conflict_67")
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
