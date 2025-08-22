import os, sys
import copy
import json
import netaddr
import ipaddress
from tqdm import tqdm
from datetime import datetime, timedelta
from source_analysis import getspemap, private_ip_list_v4, private_ip_list_v6
current_directory = sys.argv[1]
content = sys.argv[2]
if content == 'None':
    cro_file = current_directory + "/cro_data/cro_mdis_initial_" + current_directory
    agg_file = current_directory + "/cro_data/cro_mdis_" + current_directory
    cro_file_v = current_directory + "/cro_data/cro_mdis_initial_" + current_directory + "_v"
else:
    cro_file = current_directory + "/cro_data/cro_mdis_initial_" + current_directory + "_" + content
    agg_file = current_directory + "/cro_data/cro_mdis_" + current_directory + "_" + content
    cro_file_v = current_directory + "/cro_data/cro_mdis_initial_" + current_directory + "_v" + "_" + content

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
    else:
        s = pfxmap[length][pfxbin]
        s['prefix'].append(ip + '/' + str(pfxlen))
        s['asns'].append(asns)

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
    if asn == 0 or 64496 <= asn <= 131071 or 401309 <= asn <= 4294967295 or asn == 23456 or 153914 <= asn <= 196607 or 216476 <= asn <= 262143 or 274845 <= asn <= 327679 or 329728 <= asn <= 393215:
        return True
    else:
        return False


def process_roa(f, data, flag='ROA'):
    data_asn = {}
    f1 = open(f, 'r')
    for line in f1:
        if "asn" not in line:
            continue
        asn = int(line.split("asn\": \"")[1].split("\"")[0][2:])
        prefix = line.split("prefix\": \"")[1].split("\"")[0]
        maxLength = int(line.split("maxLength\": ")[1].split(",")[0])
        ty_pe = line.split("type\": \"")[1].split("\"")[0]
        uri = line.split("uri\": \"")[1].split("\"")[0]
        tal = line.split("tal\": \"")[1].split("\"")[0]
        validity_notBefore = line.split("notBefore\": \"")[1].split("\"")[0]
        validity_notAfter = line.split("notAfter\": \"")[1].split("\"")[0]
        chainValidity_notBefore = line.split("chainValidity\"")[1].split("notBefore\": \"")[1].split("\"")[0]
        chainValidity_notAfter = line.split("chainValidity\"")[1].split("notAfter\": \"")[1].split("\"")[0]
        pfx = prefix.split('/')[0]
        pl = int(prefix.split('/')[1].split('\n')[0])
        if (prefix, asn, maxLength) not in data:
            data[(prefix, asn, maxLength)] = {}
            data[(prefix, asn, maxLength)]['num'] = 1
            data[(prefix, asn, maxLength)]['time'] = [validity_notBefore, validity_notAfter, chainValidity_notBefore, chainValidity_notAfter]
            data[(prefix, asn, maxLength)]['type'] = [ty_pe]
            data[(prefix, asn, maxLength)]['uri'] = uri
            data[(prefix, asn, maxLength)]['tal'] = [tal]
        else:
            print("error")
        if asn not in data_asn:
            data_asn[asn] = {}
            data_asn[asn][maxLength] = [prefix]
        else:
            if maxLength not in data_asn[asn]:
                data_asn[asn][maxLength] = [prefix]
            else:
                data_asn[asn][maxLength].append(prefix)

    f1.close()
    return data_asn



def roa_aggregate(data_asn, data):
    #process aggregate
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
            data[(prefix, asn, maxLength)]['type'] = ['irr']
            data[(prefix, asn, maxLength)]['uri'] = ''
            data[(prefix, asn, maxLength)]['tal'] = [source]
        else:
            data[(prefix, asn, maxLength)]['num'] = +1
            data[(prefix, asn, maxLength)]['type'].append('irr')
            data[(prefix, asn, maxLength)]['tal'].append(source)


def roa_write_cro(roa_file):
    # start process
    f1 = open(roa_file, 'r')
    f2 = open(cro_file, 'w')
    f2_v = open(cro_file_v, 'w')

    # flag = 0: lines before "roas": [, flag = 1: lines after "roas": [
    flag = 0
    for line in f1:
        if "asn" not in line:
            if flag == 0:
                f2.write(line)
                f2_v.write(line)
            continue
        if flag == 0:
            flag = 1
        if line[-2] != ',':
            f2.write(line[:-1] + ',\n')
            
            prefix = line.split('\"prefix\": \"')[1].split('\"')[0]
            if ':' in prefix:
                v = 'ipv6'
            else:
                v = 'ipv4'
            line_list = line.split(', \"source\"')
            f2_v.write(line_list[0] + ', \"version": ' + v + ', \"source\"' + line_list[1][:-1] + ',\n')
            
        else:
            f2.write(line)
            
            prefix = line.split('\"prefix\": \"')[1].split('\"')[0]
            if ':' in prefix:
                v = 'ipv6'
            else:
                v = 'ipv4'
            line_list = line.split(', \"source\"')
            f2_v.write(line_list[0] + ', \"version": ' + v + ', \"source\"' + line_list[1])
            

    f1.close()
    f2.close()
    #f2_v.close()

def read_rectification_cro(new_cro_file, spemap_v4, spemap_v6):
    num = 0
    f1 = open(cro_file, 'a')
    f1_v = open(cro_file_v, 'a')
    if not os.path.exists(new_cro_file):
        f1.close()
        return 0

    f2 = open(new_cro_file, 'r')
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
        f1.write("{ \"asn\": \"AS" + str(asn) + "\", \"prefix\": \"" + prefix + "\", \"maxLength\": " + str(maxLength) + ", \"source\": [ { \"type\": \"CRO_correction\", \"uri\": \"\", \"tal\": \"\", \"validity\": { \"notBefore\": \"\", \"notAfter\": \"\" }, \"chainValidity\": { \"notBefore\": \"\", \"notAfter\": \"\" } }] },\n")
        num += 1
        if ':' in prefix:
            v = 'ipv6'
        else:
            v = 'ipv4'
        f1_v.write("{ \"asn\": \"AS" + str(asn) + "\", \"prefix\": \"" + prefix + "\", \"maxLength\": " + str(maxLength) + ", \"version\": " + v + ", \"source\": [ { \"type\": \"CRO_correction\", \"uri\": \"\", \"tal\": \"\", \"validity\": { \"notBefore\": \"\", \"notAfter\": \"\" }, \"chainValidity\": { \"notBefore\": \"\", \"notAfter\": \"\" } }] },\n")

    f1.close()
    f2.close()
    f1_v.close()
    return num

def to_cro(add_num, cfile):
    with open(cfile, 'r') as file:
        lines = file.readlines()

    # 
    if lines:
        # ，
        last_line = lines[-1].rstrip('\n,')  # 
        lines[-1] = last_line + '\n'

        num = int(lines[2].split(': ')[1].split(',')[0])
        lines[2] = '\"generated\": ' + str(num + add_num) + ',\n'

        # 
        with open(cfile, 'w') as file:
            file.writelines(lines)
            file.write("]}\n")
    

def aggregate_roas(roas):
    # devided roas by ASN 
    roas_by_asn = {}
    aggregated_roas = []
    aggregated_roas_v6 = []

    #num print init
    cro_v4_num = 0
    cro_v6_num = 0
    cro_agg_v4_num = 0

    #pre process, devide by ASN, get roas_by_asn[asn]:list of roas
    for roa in roas:
        asn = roa['asn']
        prefix = roa['prefix']
        if ':' in prefix:
            # print("Not process IPv6")
            this_record = {}
            this_record['asn'] = roa['asn']
            this_record['prefix'] = roa['prefix']
            this_record['maxLength'] = roa['maxLength']
            this_record['source'] = roa['source']
            cro_v6_num += 1
            aggregated_roas_v6.append(this_record)
            continue
        if asn not in roas_by_asn:
            roas_by_asn[asn] = []
        roas_by_asn[asn].append(roa)
    
    # aggregate roas
    pbar = tqdm(total=len(roas_by_asn), desc="", leave=True)
    for asn in roas_by_asn.keys():
        pbar.set_description(f"Processing {asn}")
        agg_set = {}
        #ipv4
        ipv4_len = 32
        for i in range(ipv4_len+1):
            agg_set[i] = {}

        for cro in roas_by_asn[asn]:
            cro_v4_num += 1
            prefix_ip = ipaddress.ip_network(cro['prefix'])
            for this_length in range(prefix_ip.prefixlen, cro['maxLength'] + 1):
                for subnet in list(prefix_ip.subnets(new_prefix=this_length)):
                    if str(subnet) not in agg_set[this_length].keys():
                        agg_set[this_length][str(subnet)] = []            
                        for source_i in cro['source']:
                            source_record = {}
                            source_record['type'] = source_i['type']
                            source_record['tal'] = source_i['tal']
                            agg_set[this_length][str(subnet)].append(source_record)
                    

        for i in range(0, ipv4_len+1):
            for this_prefix_str in agg_set[i].keys():
                this_prefix = ipaddress.ip_network(this_prefix_str)
                maxlength = this_prefix.prefixlen
                #for each possible maxlength   
                this_maxlength_can = 1              
                while(1):
                    for subnet in list(this_prefix.subnets(new_prefix=maxlength)):
                        if str(subnet) not in agg_set[maxlength].keys():
                            this_maxlength_can = 0
                            break
                    if this_maxlength_can==0 or maxlength==ipv4_len:
                        if this_maxlength_can==0:
                            maxlength -= 1
                        elif this_maxlength_can==1 and maxlength==ipv4_len:
                            # do nothing
                            maxlength -= 0
                        this_record = {}
                        this_record['asn'] = asn
                        this_record['prefix'] = str(this_prefix)
                        this_record['maxLength'] = maxlength
                        this_record['source'] = []
                        type_set = set()
                        tal_set = set()
                        if str(this_prefix) not in agg_set[i]:
                            print("Wrong!", this_prefix, "Dissappear!")
                            print(this_prefix)
                            print(maxlength)
                            print(i)
                            print(this_prefix_str)
                            a = str(this_prefix) in agg_set[16]
                            print(a)
                            
                        for source_i in agg_set[i][str(this_prefix)]:
                            # print(source_i)
                            type_list_temp = source_i['type'].split(', ')
                            for type_1 in type_list_temp:
                                type_set.add(type_1)
                            tal_list_temp = source_i['tal'].split(', ')
                            for tal_1 in tal_list_temp:
                                tal_set.add(tal_1)
                            #tal_set.add(source_i['tal'])
                        for subnetlen in range(this_prefix.prefixlen+1, maxlength+1):
                            for subnet in list(this_prefix.subnets(new_prefix=subnetlen)):
                                if str(subnet) not in agg_set[subnetlen]:
                                    print("Wrong!", subnet, "Dissappear!")
                                for source_i in agg_set[subnetlen][str(subnet)]:
                                    type_parts = [part.strip() for part in source_i['type'].split(', ')]
                                    for type_part in type_parts:
                                        type_set.add(type_part)
                                    tal_parts = [part.strip() for part in source_i['tal'].split(', ')]
                                    for tal_part in tal_parts:
                                        tal_set.add(tal_part)
                                del agg_set[subnetlen][str(subnet)]
                        source_record = {}
                        type_str = ', '.join(sorted(type_set))
                        tal_str = ', '.join(sorted(tal_set))
                        source_record['type'] = type_str
                        # print(type_set)
                        source_record['tal'] = tal_str
                        # print(tal_set)
                        this_record['source'].append(source_record)
                        cro_agg_v4_num += 1
                        aggregated_roas.append(this_record)
                        break
                    else:
                        maxlength += 1
        pbar.update(1)  
    
    f1 = open(agg_file, 'w')
    
    f1.write("{\n")
    f1.write("\"metadata\": {\n")
    f1.write("\"generated\": " + str(cro_agg_v4_num + cro_v6_num) + ",\n")
    f1.write("\"generatedTime\": \"" + str(datetime.now()) + "\"\n")
    f1.write("},\n")
    f1.write("\"roas\": [\n")

    for temp in aggregated_roas:
        f1.write("{ \"asn\": \"" + temp['asn'] + "\", \"prefix\": \"" + temp['prefix'] + "\", \"maxLength\": " + str(temp['maxLength']) +", \"source\": [ { \"type\": \"" + temp['source'][0]['type'] + "\", \"tal\": \"" + temp['source'][0]['tal'] + "\"}]},\n")
        
    for temp in aggregated_roas_v6:
        f1.write("{ \"asn\": \"" + temp['asn'] + "\", \"prefix\": \"" + temp['prefix'] + "\", \"maxLength\": " + str(temp['maxLength']) +", \"source\": [ { \"type\": \"" + temp['source'][0]['type'] + "\", \"tal\": \"" + temp['source'][0]['tal'] + "\"}]},\n")
        
    f1.close()

    to_cro(0, agg_file)



def main():
    
    start_time = datetime.now()
    start_timetamp = start_time.strftime("%Y%m%d %H:%M:%S")
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        log.write(f"{content}: {start_timetamp} generate mdis cro started\n")

    
    year, month, day = map(str, current_directory.split('-'))

    if content == "None":
        file = current_directory + "/cro_data/cro_" + current_directory
    else:
        file = current_directory + "/cro_data/cro_" + current_directory + "_" + content

    roa_write_cro(file)


    spemap_v4 = {}
    spemap_v6 = {}
    getspemap(spemap_v4, spemap_v6, private_ip_list_v4, private_ip_list_v6)

    new_cro_file = current_directory + "/bgp_route/result/mdis_cro-" + current_directory + "_" + content
    add_num = read_rectification_cro(new_cro_file, spemap_v4, spemap_v6)

    to_cro(add_num, cro_file)
    to_cro(add_num, cro_file_v)
    
    with open(cro_file, "r") as file:
        cro_data = json.load(file)
    
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        log.write(f"{content}: {start_timetamp} aggregate cro started\n")

    aggregate_roas(cro_data['roas'])    
    
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        duration = finish_time - start_time
        log.write(f"{content}: {finish_timestamp} generate mdis cro ended, used {duration}\n")

if __name__ == '__main__':
    main()
