import json
import numpy as np
import copy
import pandas as pd
import ipaddress
import netaddr
import time

#private_as_list = list(range(64512,65535,1)) + list(range(4200000000,4294967294,1))
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


def process_bgp(f, data, spemap_v4, spemap_v6):
    num = 0
    with open(f, 'r') as file:
        json_data = json.load(file)
        routes = json_data['routes']
        for route in routes:
            pfx = route['prefix'].split('/')[0]
            pl = int(route['prefix'].split('/')[1].split('\n')[0])
            if ':' in route['prefix'] and checkspepfx(spemap_v6, pfx, pl)==True:
                continue
            if '.' in route['prefix'] and checkspepfx(spemap_v4, pfx, pl)==True:
                continue
            if checkspeasn(int(route['asn'])) == True:
                continue
            if route['prefix'] == '0.0.0.0/0' or route['prefix'] == '::/0':
                continue
            if ':' in route['prefix'] and route['prefix'] in bogon_ip_dict_v6:
                continue
            if '.' in route['prefix'] and route['prefix'] in bogon_ip_dict_v4:
                continue
            if int(route['asn']) in bogon_asn:
                continue
            if (route['prefix'], route['asn']) not in data:
                data[(route['prefix'], route['asn'])] = {}
                data[(route['prefix'], route['asn'])]['num'] = 1
                data[(route['prefix'], route['asn'])]['valid'] = []
                data[(route['prefix'], route['asn'])]['invalid'] = []
            else:
                data[(route['prefix'], route['asn'])]['num'] += 1



def process_irr(f, data, spemap_v4, spemap_v6):
    f1 = open(f, 'r', encoding = "ISO-8859-1")
    for line in f1:
        prefix = line.split(' ')[1].split('\n')[0]
        asn = int(line.split(' ')[0])
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
        if ':' in pfx and pfx in bogon_ip_dict_v6:
            continue
        if '.' in pfx and pfx in bogon_ip_dict_v4:
            continue
        if asn in bogon_asn:
            continue
        '''
        if (prefix, asn, maxlen) not in data:
            data[(prefix, asn, maxlen)] = {}
            data[(prefix, asn, maxlen)]['num'] = 1
            data[(prefix, asn, maxlen)]['valid'] = []
            data[(prefix, asn, maxlen)]['invalid'] = []
        else:
            data[(prefix, asn, maxlen)]['num'] += 1
    f1.close()
    


def process_roa(f, data, spemap_v4, spemap_v6):
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
        #if 64512 < asn < 65535:
        #    print("Error", prefix, asn, maxLength)
        pfx = prefix.split('/')[0]
        pl = int(prefix.split('/')[1].split('\n')[0])
        if ':' in pfx and checkspepfx(spemap_v6, pfx, pl)==True:
            continue
        if '.' in pfx and checkspepfx(spemap_v4, pfx, pl)==True:
            continue
        if checkspeasn(asn) == True:
            continue
        if prefix == '0.0.0.0/0' or prefix == '::/0':
            continue
        '''
        if ':' in pfx and pfx in bogon_ip_dict_v6:
            continue
        if '.' in pfx and pfx in bogon_ip_dict_v4:
            continue
        if asn in bogon_asn:
            continue
        '''
        if (prefix, asn, maxLength) not in data:
            data[(prefix, asn, maxLength)] = {}
            data[(prefix, asn, maxLength)]['num'] = 1
            data[(prefix, asn, maxLength)]['time'] = [[validity_notBefore, validity_notAfter, chainValidity_notBefore, chainValidity_notAfter]]
            data[(prefix, asn, maxLength)]['initial'] = True
            data[(prefix, asn, maxLength)]['initial-prefix'] = []
            data[(prefix, asn, maxLength)]['valid'] = []
            data[(prefix, asn, maxLength)]['invalid'] = []
        else:
            data[(prefix, asn, maxLength)]['num'] += 1
            data[(prefix, asn, maxLength)]['time'].append([validity_notBefore, validity_notAfter, chainValidity_notBefore, chainValidity_notAfter])

    f1.close()

def process_roa_aggregate(f, data, spemap_v4, spemap_v6):
    f1 = open(f, 'r')
    for line in f1:
        if "asn" not in line:
            continue
        asn = int(line.split("asn\": \"")[1].split("\"")[0][2:])
        prefix = line.split("prefix\": \"")[1].split("\"")[0]
        pfx = prefix.split('/')[0]
        pl = int(prefix.split('/')[1].split('\n')[0])
        if ':' in pfx and checkspepfx(spemap_v6, pfx, pl)==True:
            continue
        if '.' in pfx and checkspepfx(spemap_v4, pfx, pl)==True:
            continue
        if checkspeasn(asn) == True:
            continue
        if prefix == '0.0.0.0/0' or prefix == '::/0':
            continue
        '''
        if ':' in pfx and pfx in bogon_ip_dict_v6:
            continue
        if '.' in pfx and pfx in bogon_ip_dict_v4:
            continue
        if asn in bogon_asn:
            continue
        '''
        maxLength = int(line.split("maxLength\": ")[1].split(",")[0])
        ty_pe = line.split("type\": \"")[1].split("\"")[0]
        uri = line.split("uri\": \"")[1].split("\"")[0]
        tal = line.split("tal\": \"")[1].split("\"")[0]
        validity_notBefore = line.split("notBefore\": \"")[1].split("\"")[0]
        validity_notAfter = line.split("notAfter\": \"")[1].split("\"")[0]
        chainValidity_notBefore = line.split("chainValidity\"")[1].split("notBefore\": \"")[1].split("\"")[0]
        chainValidity_notAfter = line.split("chainValidity\"")[1].split("notAfter\": \"")[1].split("\"")[0]

        source_list = []
        source_initial = line.split("source_initial\": \"")[1].split("\"")[0]
        temp_list = source_initial.split(')')
        for temp in temp_list:
            if "(" not in temp:
                continue
            temp = temp.split('(')[1]
            temp = temp.split(',')
            temp_prefix = temp[0].split('\'')[1]
            temp_asn = int(temp[1])
            temp_maxlen = int(temp[2])
            source_list.append((temp_prefix, temp_asn, temp_maxlen))

        if (prefix, asn, maxLength) not in data:
            data[(prefix, asn, maxLength)] = {}
            data[(prefix, asn, maxLength)]['num'] = 1
            data[(prefix, asn, maxLength)]['time'] = [[validity_notBefore, validity_notAfter, chainValidity_notBefore, chainValidity_notAfter]]
            data[(prefix, asn, maxLength)]['initial'] = False
            data[(prefix, asn, maxLength)]['initial-prefix'] = source_list
            data[(prefix, asn, maxLength)]['valid'] = []
            data[(prefix, asn, maxLength)]['invalid'] = []
        else:
            data[(prefix, asn, maxLength)]['initial-prefix'] = source_list


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

def process_asn2n(dic_asncsv, dic_asname, dic_orgid, dic_asn):
    # construct ASN-Name dict
    
    # This block is use the ASN2N.csv https://www.cidr-report.org/as2.0/autnums.html

    df_asn2n = pd.read_csv('ASN2N.csv')
    as_list = df_asn2n['ASN'].values.tolist()
    asname_list = df_asn2n['ASName'].values.tolist()
    ascountry_list = df_asn2n['Country'].values.tolist()
    for i in range(len(as_list)):
        dic_asncsv[as_list[i]] = ascountry_list[i]
        dic_asname[as_list[i]] = asname_list[i]
    
    # This block is use the 20240101.as-org2info.txt https://publicdata.caida.org/datasets/as-organizations/
    f = '20240101.as-org2info.txt'
    try:
        f1 = open(f, 'r')
        print(f)
    except:
        print("error", f)
        pass
    

    flag = -1
    for line in f1:
        if flag == 0:
            dic_orgid[line.split('|')[0]] = [line.split('|')[1], line.split('|')[2], line.split('|')[3], line.split('|')[4]]
        elif flag == 1:
            dic_asn[int(line.split('|')[0])] = [line.split('|')[1], line.split('|')[2], line.split('|')[3], line.split('|')[4], line.split('|')[5]]
        if "format:org_id" in line:
            flag = 0
        elif "format:aut" in line:
            flag = 1
    
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
    #for asn in asns:
        #a.add(asn)
        #a.add(asns)
    else:
        s = pfxmap[length][pfxbin]
        s['prefix'].append(ip + '/' + str(pfxlen))
        s['asns'].append(asns)
    if s['prefix'] == '103.249.14.0/23':
        print(s['asns'])


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

def checkASc2pBFS(asn, root, ty_pe, asrel_cus):
    if len(root) > 0:
        if asn in root:
            return True
        for temp in root:
            if checkASc2pBFS(asn, asrel_cus[temp][ty_pe], ty_pe, asrel_cus) == True:
                return True
    else:
        return False



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
    
        
def getirrmap(irrmap_v4, irrmap_v6, data_irr):
    for key in data_irr:
        asn = int(key[1])
        pfx = key[0]
        """ for IPv6 routes """
        if ':' in pfx:
            createROAmap(irrmap_v6, asn, pfx, 128)
        else:
            createROAmap(irrmap_v4, asn, pfx, 32)


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
                    data_bgp[(pfxstr, asn)]['valid'].append([v['vrp'], asn, maxlen])
                    #print((v, asn, maxlen))
                    data_roa[(v['vrp'], asn, maxlen)]['valid'].append([pfxstr, asn])
                elif length <= maxlen:
                    data_bgp[(pfxstr, asnset)]['invalid'].append([v['vrp'], asn, maxlen])
                    data_roa[(v['vrp'], asn, maxlen)]['invalid'].append([pfxstr, asnset])
                else:
                    data_bgp[(pfxstr, asnset)]['invalid'].append([v['vrp'], asn, maxlen])
                    data_roa[(v['vrp'], asn, maxlen)]['invalid'].append([pfxstr, asnset])
                    #return r

    if pfx_exists and r!= 'valid':
        r = 'invalid'

    return r

def rov(data_bgp, data_roa, spemap_v4, spemap_v6, dic_asn):
    roamap_v4 = {}
    roamap_v6 = {}
    pfxmap_v4 = {}
    pfxmap_v6 = {}
    #irrmap_v4 = {}
    #irrmap_v6 = {}
    #spemap_v4 = {}
    #spemap_v6 = {}

    getroamap(roamap_v4, roamap_v6, data_roa)
    getpfxmap(pfxmap_v4, pfxmap_v6, data_bgp)
    #getspemap(spemap_v4, spemap_v6, private_ip_list_v4, private_ip_list_v6)
    #getirrmap(irrmap_v4, irrmap_v6, data_irr)

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
                if checkspepfx(spemap_v6, pfx, pl)==True:
                    continue
                if checkspeasn(asns) == True:
                    continue
                if pfxstr == '0.0.0.0/0' or pfxstr == '::/0':
                    continue
                if pfx in bogon_ip_dict_v6:
                    continue
                try:
                    asn = int(list(asns)[0])
                except:
                    asn = int(asns)
                if asn in bogon_asn:
                    continue
                r_roa = rovproc(roamap_v6, pfx, pl, asns, pfxstr, data_bgp, data_roa)
    

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
                if checkspepfx(spemap_v4, pfx, pl)==True:
                    continue
                if checkspeasn(asns) == True:
                    continue
                if pfxstr == '0.0.0.0/0' or pfxstr == '::/0':
                    continue
                if pfx in bogon_ip_dict_v4:
                    continue
                try:
                    asn = int(list(asns)[0])
                except:
                    asn = int(asns)
                if asn in bogon_asn:
                    continue
                r_roa = rovproc(roamap_v4, pfx, pl, asns, pfxstr, data_bgp, data_roa)
                

def compare_time(data_bgp, data_roa):
    list_older = []
    list_newer = []
    num = 0
    for key, item in data_bgp.items():
        if len(item['invalid']) > 0 and len(item['valid']) == 0:
            num += 1
        if len(item['invalid']) > 0 and len(item['valid']) > 0:
            #item['valid'][0]
            valid_time = '1900-00-00T00:00:00Z'
            for temp in item['valid']:
                temp_time = data_roa[(temp[0], temp[1], temp[2])]['time'][0][2]
                if valid_time < temp_time:
                    valid_time = temp_time

            #data_roa[(item['valid'][0][0], item['valid'][0][1], item['valid'][0][2])]['time'][0][0]
            for temp in item['invalid']:
                temp_time = data_roa[(temp[0], temp[1], temp[2])]['time'][0][2]
                if valid_time < temp_time:
                    '''
                    if num < 100:
                        print(key)
                        print((item['valid'][0][0], item['valid'][0][1], item['valid'][0][2]), data_roa[(item['valid'][0][0], item['valid'][0][1], item['valid'][0][2])]['time'][0])
                        print((temp[0], temp[1], temp[2], data_roa[(temp[0], temp[1], temp[2])]['time'][0]))
                        num += 1
                    '''
                    list_older.append([temp[0], temp[1], temp[2]])
                else:
                    list_newer.append([temp[0], temp[1], temp[2]])
    print(len(list_older), len(list_newer))
    print(num)
            
def coverage(data, tag):
    # Initialize a list to store IP ranges
    ip_ranges_v4 = []
    ip_ranges_v6 = []

    for key, item in data.items():
        prefix = key[0]
        if prefix == "":
            continue
        if ':' in prefix:
            network = ipaddress.IPv6Network(prefix, strict=False)
            start, end = int(network.network_address), int(network.broadcast_address)
            #print(network.network_address)
            ip_ranges_v6.append((start, end))
        else:
            try:
                network = ipaddress.IPv4Network(prefix, strict=False)
                start, end = int(network.network_address), int(network.broadcast_address)
                #print(network.network_address)
                ip_ranges_v4.append((start, end))
            except:
                continue

    private_ip_ranges_v4 = []
    for prefix in private_ip_list_v4:
        network = ipaddress.IPv4Network(prefix, strict=False)
        start, end = int(network.network_address), int(network.broadcast_address)
        #print(network.network_address)
        private_ip_ranges_v4.append((start, end))
    
    private_ip_ranges_v6 = []
    for prefix in private_ip_list_v6:
        network = ipaddress.IPv6Network(prefix, strict=False)
        start, end = int(network.network_address), int(network.broadcast_address)
        #print(network.network_address)
        private_ip_ranges_v6.append((start, end))

    # v4
    # Sort the IP ranges and remove duplicates
    ip_ranges_v4.sort()
    
    # Initialize merged_ranges with the first range
    merged_ranges = [ip_ranges_v4[0]]

    # Merge overlapping and adjacent IP ranges
    for start, end in ip_ranges_v4[1:]:
        if start <= merged_ranges[-1][1] + 1:
            merged_ranges[-1] = (merged_ranges[-1][0], max(end, merged_ranges[-1][1]))
        else:
            merged_ranges.append((start, end))

    # Calculate the total length of covered IP address space
    covered_space_length = sum(end - start + 1 for start, end in merged_ranges)

    # Sort the private IP ranges and remove duplicates
    private_ip_ranges_v4.sort()
    
    # Initialize merged_ranges with the first range
    merged_ranges = [private_ip_ranges_v4[0]]

    # Merge overlapping and adjacent IP ranges
    for start, end in private_ip_ranges_v4[1:]:
        if start <= merged_ranges[-1][1] + 1:
            merged_ranges[-1] = (merged_ranges[-1][0], max(end, merged_ranges[-1][1]))
        else:
            merged_ranges.append((start, end))

    # Calculate the total length of private IP address space
    private_covered_space_length = sum(end - start + 1 for start, end in merged_ranges)


    # Calculate the percentage of coverage
    total_address_space = 2**32 - private_covered_space_length
    coverage_percentage = (covered_space_length / total_address_space) * 100

    print(f"Percentage of IPv4 address coverage: {coverage_percentage:.2f}%")

    unused_networks_ipv4 = []
    if tag:
        starts = []
        ends = [0]
        for start, end in merged_ranges:
            starts.append(start)
            ends.append(end)
        starts.append(4294967295)
        unused_ips = []
        for i in range(len(starts)):
            startip = ipaddress.IPv4Address(ends[i])
            endip = ipaddress.IPv4Address(starts[i])
            unused_ips.extend([str(ipaddr) for ipaddr in ipaddress.summarize_address_range(startip, endip)])
        unused_networks_ipv4 = netaddr.cidr_merge(unused_ips)
    
    # v6
    # Sort the IP ranges and remove duplicates
    ip_ranges_v6.sort()
    
    # Initialize merged_ranges with the first range
    try:
        merged_ranges = [ip_ranges_v6[0]]
    except:
        return unused_networks_ipv4, []

    # Merge overlapping and adjacent IP ranges
    for start, end in ip_ranges_v6[1:]:
        if start <= merged_ranges[-1][1] + 1:
            merged_ranges[-1] = (merged_ranges[-1][0], max(end, merged_ranges[-1][1]))
        else:
            merged_ranges.append((start, end))

    # Calculate the total length of covered IP address space
    covered_space_length = sum(end - start + 1 for start, end in merged_ranges)

    # Sort the private IP ranges and remove duplicates
    private_ip_ranges_v6.sort()
    
    # Initialize merged_ranges with the first range
    merged_ranges = [private_ip_ranges_v6[0]]

    # Merge overlapping and adjacent IP ranges
    for start, end in private_ip_ranges_v6[1:]:
        if start <= merged_ranges[-1][1] + 1:
            merged_ranges[-1] = (merged_ranges[-1][0], max(end, merged_ranges[-1][1]))
        else:
            merged_ranges.append((start, end))

    # Calculate the total length of covered IP address space
    private_covered_space_length = sum(end - start + 1 for start, end in merged_ranges)

    # Calculate the percentage of coverage
    total_address_space = 2**128 - private_covered_space_length
    coverage_percentage = (covered_space_length / total_address_space) * 100

    print(f"Percentage of IPv6 address coverage: {coverage_percentage:.2f}%")

    used_networks_ipv6 = []
    if tag:
        used_ips = []
        for start, end in merged_ranges:
            startip = ipaddress.IPv6Address(start)
            endip = ipaddress.IPv6Address(end)
            used_ips.extend([str(ipaddr) for ipaddr in ipaddress.summarize_address_range(startip, endip)])
        used_networks_ipv6 = netaddr.cidr_merge(used_ips)
    
    return unused_networks_ipv4, used_networks_ipv6

def process_initial_prefix(data_FRO, target_list, num_valid, tag):
    if len(target_list) == 0:
        return num_valid

    for temp in target_list:
        if temp not in data_FRO:
            num_valid += 1
            data_FRO[temp] = {}
            data_FRO[temp]['source'] = tag
            data_FRO[temp]['confidence'] = 100
            target_list_new = data_roa[temp]['initial-prefix']
            num_valid = process_initial_prefix(data_FRO, target_list_new, num_valid, tag)
    
    return num_valid
                        


def construct_FRO(data_bgp, data_roa, data_FRO, asrel_v4, asrel_v6, dic_asn, data_bgp_irr, data_irr, unused_networks_ipv4, used_networks_ipv6):
    f1 = open('sources/0909_notexist', 'w')
    num_valid = 0
    bgp_num_valid = 0

    num_valid_cross = 0
    bgp_num_valid_cross = 0
    num_valid_moas = 0
    bgp_num_valid_moas = 0
    num_valid_org = 0
    bgp_num_valid_org = 0
    num_valid_c2p = 0
    bgp_num_valid_c2p = 0
    num_valid_invalid = 0

    num_invalid = 0
    num_invalid_org = 0
    num_invalid_cross = 0
    bgp_num_invalid_cross = 0
    bgp_num_invalid_org = 0
    num_invalid_c2p = 0
    bgp_num_invalid_c2p = 0
    num_invalid_special = 0
    bgp_num_invalid_special = 0
    num_invalid_as0 = 0
    bgp_num_invalid_as0 = 0
    num_invalid_irr_valid = 0
    bgp_num_invalid_irr_valid = 0
    
    num_unknown = 0
    num_unknown_notexist = 0
    print("STEP 1")
    for key, item in data_roa.items():
        # step 1: ROA-valid
        if len(item['valid']) > 0 and len(item['invalid']) == 0:
            if key in data_FRO:
                continue
            num_valid += 1
            data_FRO[key] = {}
            data_FRO[key]['source'] = 'ROA-valid'
            data_FRO[key]['confidence'] = 100
            bgp_num_valid += len(item['valid'])
            
            num_valid = process_initial_prefix(data_FRO, item['initial-prefix'], num_valid, 'ROA-valid-sub')
            '''
            if len(item['initial-prefix']) > 0:
                for temp in item['initial-prefix']:
                    if temp not in data_FRO:
                        num_valid += 1
                        data_FRO[temp] = {}
                        data_FRO[temp]['source'] = 'ROA-valid-sub'
                        data_FRO[temp]['confidence'] = 100
            '''
    print("STEP 2")
    for key, item in data_roa.items():       
        if len(item['valid']) > 0 and len(item['invalid']) > 0:
            if key in data_FRO:
                continue
            num_valid_invalid += 1
            # step 2: ROA-valid-cross
            flag = 0
            temp_list = copy.deepcopy(item['invalid'])
            for temp in item['invalid']:
                if len(data_bgp[(temp[0], temp[1])]['valid']) == 0:
                    flag = 1
                else:
                    temp_list.remove(temp)
            
            if flag == 0:
                num_valid_cross += 1
                data_FRO[key] = {}
                data_FRO[key]['source'] = 'ROA-valid-cross'
                data_FRO[key]['confidence'] = 100
                bgp_num_valid_cross += len(item['valid']) + len(item['invalid'])
                num_valid_cross = process_initial_prefix(data_FRO, item['initial-prefix'], num_valid_cross, 'ROA-valid-cross-sub')
                '''
                if len(item['initial-prefix']) > 0:
                    for temp in item['initial-prefix']:
                        if temp not in data_FRO:
                            num_valid_cross += 1
                            data_FRO[temp] = {}
                            data_FRO[temp]['source'] = 'ROA-valid-cross-sub'
                            data_FRO[temp]['confidence'] = 100
                '''
                continue
            
            # step 3: ROA-valid-org
            flag = 0
            flag_org = 0
            temp_list_1 = copy.deepcopy(temp_list)
            for temp in item['invalid']:
                if temp in temp_list_1:
                    for temp_valid in item['valid']:
                        if int(temp_valid[1]) in dic_asn and int(temp[1]) in dic_asn and dic_asn[temp_valid[1]][2] == dic_asn[int(temp[1])][2]:
                            flag = 3
                            try:
                                temp_list_1.remove(temp)
                            except:
                                pass
                    if flag != 3:
                        flag_org = 1
            
            if flag_org == 0:
                num_valid_org += 1
                data_FRO[key] = {}
                data_FRO[key]['source'] = 'ROA-valid-org'
                data_FRO[key]['confidence'] = 100
                bgp_num_valid_org += len(item['valid']) + len(item['invalid'])
                if len(item['initial-prefix']) > 0:
                    for temp in item['initial-prefix']:
                        if temp not in data_FRO:
                            num_valid_org += 1
                            data_FRO[temp] = {}
                            data_FRO[temp]['source'] = 'ROA-valid-org-sub'
                            data_FRO[temp]['confidence'] = 100
                continue
            
            # step 4: ROA-valid-c2p
            flag = 0
            flag_c2p = 0
            temp_list_2 = copy.deepcopy(temp_list_1)
            for temp in item['invalid']:
                if temp in temp_list_2:
                    for temp_valid in item['valid']:
                        if '/' in temp_valid[0]:
                            if checkASc2p(temp_valid[1], int(temp[1]), asrel_v4, asrel_cus_v4):
                                flag = 2
                                try:
                                    temp_list_2.remove(temp)
                                except:
                                    pass
                            '''
                            if (int(temp_valid[1]), int(temp[1])) in asrel_v4 and asrel_v4[(int(temp_valid[1]), int(temp[1]))] == -1:
                                flag = 2
                            elif (int(temp[1]), int(temp_valid[1])) in asrel_v4 and asrel_v4[(int(temp[1]), int(temp_valid[1]))] == -1:
                                flag = 2
                            '''
                        elif ':' in temp_valid[0]:
                            if checkASc2p(temp_valid[1], int(temp[1]), asrel_v6, asrel_cus_v6):
                                flag = 2
                                try:
                                    temp_list_2.remove(temp)
                                except:
                                    pass
                            '''
                            if (int(temp_valid[1]), int(temp[1])) in asrel_v6 and asrel_v6[(int(temp_valid[1]), int(temp[1]))] == -1:
                                flag = 2
                            elif (int(temp[1]), int(temp_valid[1])) in asrel_v6 and asrel_v6[(int(temp[1]), int(temp_valid[1]))] == -1:
                                flag = 2
                            '''
                    
                    if flag != 2:
                        flag_c2p = 1

            if flag_c2p == 0:
                num_valid_c2p += 1
                bgp_num_valid_c2p += len(item['valid']) + len(item['invalid'])
                data_FRO[key] = {}
                data_FRO[key]['source'] = 'ROA-valid-c2p'
                data_FRO[key]['confidence'] = 100
                num_valid_c2p = process_initial_prefix(data_FRO, item['initial-prefix'], num_valid_c2p, 'ROA-valid-c2p-sub')
                continue


            
            '''
            if num_valid_invalid < 5:
                if num_valid_invalid < 1:
                    print("===========ROA-valid-invalid-remaining===========")
                print("======" + str(num_valid_invalid) + "======", key)
                print("valid:", item['valid'])
                for temp in temp_list_2: #item['invalid']:
                    if len(data_bgp[(temp[0], temp[1])]['valid']) == 0:
                        print("invalid:", temp)
            '''
    print("STEP 5")
    for key, item in data_roa.items():
        if len(item['valid']) == 0 and len(item['invalid']) > 0:
            if key in data_FRO:
                continue
            num_invalid += 1

            # step : ROA-invalid-cross
            flag = 0
            temp_list = copy.deepcopy(item['invalid'])
            for temp in item['invalid']:
                if len(data_bgp[(temp[0], temp[1])]['valid']) == 0:
                    flag = 1
                else:
                    temp_list.remove(temp)
            
            if flag == 0:
                num_invalid_cross += 1
                data_FRO[key] = {}
                data_FRO[key]['source'] = 'ROA-invalid-cross'
                data_FRO[key]['confidence'] = 100
                bgp_num_invalid_cross += len(item['valid']) + len(item['invalid'])
                num_invalid_cross = process_initial_prefix(data_FRO, item['initial-prefix'], num_invalid_cross, 'ROA-invalid-cross-sub')
                '''
                if len(item['initial-prefix']) > 0:
                    for temp in item['initial-prefix']:
                        if temp not in data_FRO:
                            num_valid_cross += 1
                            data_FRO[temp] = {}
                            data_FRO[temp]['source'] = 'ROA-valid-cross-sub'
                            data_FRO[temp]['confidence'] = 100
                '''
                continue

            # step : ROA-invalid-org
            flag = 0
            flag_org = 0
            temp_list_1 = copy.deepcopy(temp_list)
            for temp in item['invalid']:
                if temp in temp_list_1:
                    if int(key[1]) in dic_asn and int(temp[1]) in dic_asn and dic_asn[key[1]][2] == dic_asn[int(temp[1])][2]:
                        flag = 3
                        try:
                            temp_list_1.remove(temp)
                        except:
                            pass
                if flag != 3:
                    flag_org = 1
            
            if flag_org == 0:
                num_invalid_org += 1
                data_FRO[key] = {}
                data_FRO[key]['source'] = 'ROA-invalid-org'
                data_FRO[key]['confidence'] = 100
                bgp_num_invalid_org += len(item['valid']) + len(item['invalid'])
                num_invalid_org = process_initial_prefix(data_FRO, item['initial-prefix'], num_invalid_org, 'ROA-invalid-org-sub')
                continue
                '''
                if len(item['initial-prefix']) > 0:
                    for temp in item['initial-prefix']:
                        if temp not in data_FRO:
                            num_invalid_org += 1
                            data_FRO[temp] = {}
                            data_FRO[temp]['source'] = 'ROA-invalid-org-sub'
                            data_FRO[temp]['confidence'] = 100
                continue
                '''
            # step 6: ROA-invalid-c2p considering Route Aggregation
            flag = 0
            flag_c2p = 0
            temp_list_2 = copy.deepcopy(temp_list_1)
            for temp in item['invalid']:
                if temp in temp_list_2:
                    if '/' in key[0]:
                        if checkASc2p(key[1], int(temp[1]), asrel_v4, asrel_cus_v4):
                            flag = 2
                            try:
                                temp_list_2.remove(temp)
                            except:
                                pass
                            
                    elif ':' in key[0]:
                        if checkASc2p(key[1], int(temp[1]), asrel_v6, asrel_cus_v6):
                            flag = 2
                            try:
                                temp_list_2.remove(temp)
                            except:
                                pass
                    
                    if flag != 2:
                        flag_c2p = 1

            if flag_c2p == 0:
                num_invalid_c2p += 1
                bgp_num_invalid_c2p += len(item['valid']) + len(item['invalid'])
                data_FRO[key] = {}
                data_FRO[key]['source'] = 'ROA-invalid-c2p'
                data_FRO[key]['confidence'] = 100
                num_invalid_c2p = process_initial_prefix(data_FRO, item['initial-prefix'], num_invalid_c2p, 'ROA-invalid-c2p-sub')
                continue
            
            

            for temp in temp_list_2:
                
                if temp[1] == 35913 or (temp[1] == 21003 and key[1] == 19905):
                    num_invalid_special += 1
                    continue
                if key[1] == 0:
                    num_invalid_as0 += 1
                    continue
                '''
                if len(data_bgp_irr[(temp[0], temp[1])]['valid']) > 0:# and len(data_bgp_irr[(temp[0], temp[1])]['invalid']) == 0:
                    num_invalid_irr_valid += 1
                    if num_invalid_irr_valid < 20:
                        if num_invalid_irr_valid == 1:
                            print("===========ROA-invalid-IRR-valid===========")
                        print("======" + str(num_invalid_irr_valid) + "======", key)
                        print("invalid:", item['invalid'])
                        print("IRR valid:", data_bgp_irr[(temp[0], temp[1])]['valid'])
                        print("IRR invalid:", data_bgp_irr[(temp[0], temp[1])]['invalid'])
                '''

    print("STEP 6")
    for key, item in data_roa.items(): 
        if len(item['valid']) == 0 and len(item['invalid']) == 0:
            if key in data_FRO:
                continue
            num_unknown += 1
            # step 7: ROA-unknown-notexist considering the Prefix not exists in RIB
            flag = 0

            if '.' in key[0]:
                for temp in unused_networks_ipv4:
                    if ipaddress.IPv4Network(key[0]).subnet_of(ipaddress.IPv4Network(str(temp))):
                        num_unknown_notexist += 1
                        f1.write("{ \"asn\": \"AS" + str(key[1]) + "\", \"prefix\": \"" + key[0] + "\", \"maxLength\": " + str(key[2]) + ", \"source\": [ { \"type\": \"roa\", \"uri\": \"\", \"tal\": \"\", \"validity\": { \"notBefore\": \"\", \"\": \"\" }, \"chainValidity\": { \"notBefore\": \"\", \"notAfter\": \"\" } }]}\n")
                        flag = 1
                        break
            elif ':' in key[0]:
                '''
                num_unknown_notexist += 1
                #f1.write("{ \"asn\": \"AS" + str(key[1]) + "\", \"prefix\": \"" + key[0] + "\", \"maxLength\": " + str(key[2]) + ", \"source\": [ { \"type\": \"roa\", \"uri\": \"\", \"tal\": \"\", \"validity\": { \"notBefore\": \"\", \"\": \"\" }, \"chainValidity\": { \"notBefore\": \"\", \"notAfter\": \"\" } }]}\n")
                flag = 1
                break
                '''
                for temp in used_networks_ipv6:
                    if ipaddress.IPv6Network(key[0]).subnet_of(ipaddress.IPv6Network(str(temp))):
                        flag = 2
                        break
                
            if flag == 2:
                num_unknown_notexist += 1
                f1.write("{ \"asn\": \"AS" + str(key[1]) + "\", \"prefix\": \"" + key[0] + "\", \"maxLength\": " + str(key[2]) + ", \"source\": [ { \"type\": \"roa\", \"uri\": \"\", \"tal\": \"\", \"validity\": { \"notBefore\": \"\", \"\": \"\" }, \"chainValidity\": { \"notBefore\": \"\", \"notAfter\": \"\" } }]}\n")
                continue
                        
            elif flag == 1:
                continue
            
            
            if num_unknown < 10:
                print(key)
            
    f1.close()

    print(num_valid, num_valid_invalid, num_invalid, num_unknown, num_unknown_notexist, num_invalid_irr_valid, num_invalid_special, num_invalid_as0)
    print("Done Construct Step 1, ROA num: " + str(num_valid) + " (" + str(round(num_valid / len(data_roa) * 100 ,2)) + "%), BGP num: " + str(bgp_num_valid) + " (" + str(round(bgp_num_valid / len(data_bgp) * 100, 2)) + "%)")
    print("Done Construct Step 2, ROA num: " + str(num_valid_cross) + " (" + str(round(num_valid_cross / len(data_roa) * 100 ,2)) + "%), BGP num: " + str(bgp_num_valid_cross) + " (" + str(round(bgp_num_valid_cross / len(data_bgp) * 100, 2)) + "%), total ROA num: " + str(num_valid + num_valid_cross) + " (" + str(round((num_valid + num_valid_cross) / len(data_roa) * 100, 2)) + "%), total BGP num: " + str(bgp_num_valid + bgp_num_valid_cross) + " (" + str(round((bgp_num_valid + bgp_num_valid_cross) / len(data_bgp) * 100, 2)) + "%)")
    print("Done Construct Step 3, ROA num: " + str(num_valid_org) + " (" + str(round(num_valid_org / len(data_roa) * 100 ,2)) + "%), BGP num: " + str(bgp_num_valid_org) + " (" + str(round(bgp_num_valid_org / len(data_bgp) * 100, 2)) + "%), total ROA num: " + str(num_valid + num_valid_cross + num_valid_org) + " (" + str(round((num_valid + num_valid_cross + num_valid_org) / len(data_roa) * 100, 2)) + "%), total BGP num: " + str(bgp_num_valid + bgp_num_valid_cross + bgp_num_valid_org) + " (" + str(round((bgp_num_valid + bgp_num_valid_cross + bgp_num_valid_org) / len(data_bgp) * 100, 2)) + "%)")
    print("NOT Done Construct Step 4, ROA num: " + str(num_valid_c2p) + " (" + str(round(num_valid_c2p / len(data_roa) * 100 ,2)) + "%), BGP num: " + str(bgp_num_valid_c2p) + " (" + str(round(bgp_num_valid_c2p / len(data_bgp) * 100, 2)) + "%), total ROA num: " + str(num_valid + num_valid_cross + num_valid_org) + " (" + str(round((num_valid + num_valid_cross) / len(data_roa) * 100, 2)) + "%), total BGP num: " + str(bgp_num_valid + bgp_num_valid_cross) + " (" + str(round((bgp_num_valid + bgp_num_valid_cross) / len(data_bgp) * 100, 2)) + "%)")
    print("Done Construct Step 5, ROA num: " + str(num_invalid_cross) + " (" + str(round(num_invalid_cross / len(data_roa) * 100 ,2)) + "%), BGP num: " + str(bgp_num_invalid_cross) + " (" + str(round(bgp_num_invalid_cross / len(data_bgp) * 100, 2)) + "%), total ROA num: " + str(num_valid + num_valid_cross + num_valid_org + num_invalid_cross) + " (" + str(round((num_valid + num_valid_cross + num_valid_org + num_invalid_cross) / len(data_roa) * 100, 2)) + "%), total BGP num: " + str(bgp_num_valid + bgp_num_valid_cross + bgp_num_valid_org + bgp_num_invalid_cross) + " (" + str(round((bgp_num_valid + bgp_num_valid_cross+ bgp_num_valid_org + bgp_num_invalid_cross) / len(data_bgp) * 100, 2)) + "%)")
    print("Done Construct Step 6, ROA num: " + str(num_invalid_org) + " (" + str(round(num_invalid_org / len(data_roa) * 100 ,2)) + "%), BGP num: " + str(bgp_num_invalid_org) + " (" + str(round(bgp_num_invalid_org / len(data_bgp) * 100, 2)) + "%), total ROA num: " + str(num_valid + num_valid_cross + num_valid_org + num_invalid_cross + num_invalid_org) + " (" + str(round((num_valid + num_valid_cross + num_valid_org + num_invalid_cross + num_invalid_org) / len(data_roa) * 100, 2)) + "%), total BGP num: " + str(bgp_num_valid + bgp_num_valid_cross + bgp_num_valid_org + bgp_num_invalid_cross + bgp_num_invalid_org) + " (" + str(round((bgp_num_valid + bgp_num_valid_cross+ bgp_num_valid_org + bgp_num_invalid_cross + bgp_num_invalid_org) / len(data_bgp) * 100, 2)) + "%)")
    print("NOT Done Construct Step 7, ROA num: " + str(num_invalid_c2p) + " (" + str(round(num_invalid_c2p / len(data_roa) * 100 ,2)) + "%), BGP num: " + str(bgp_num_invalid_c2p) + " (" + str(round(bgp_num_invalid_c2p / len(data_bgp) * 100, 2)) + "%), total ROA num: " + str(num_valid + num_valid_cross + num_valid_org + num_invalid_org) + " (" + str(round((num_valid + num_valid_cross + num_valid_org + num_invalid_org) / len(data_roa) * 100, 2)) + "%), total BGP num: " + str(bgp_num_valid + bgp_num_valid_cross + bgp_num_valid_org + bgp_num_invalid_org) + " (" + str(round((bgp_num_valid + bgp_num_valid_cross+ bgp_num_valid_org + bgp_num_invalid_org) / len(data_bgp) * 100, 2)) + "%)")
    print("Done Construct Step 8, ROA num: " + str(num_unknown_notexist) + " (" + str(round(num_unknown_notexist / len(data_roa) * 100 ,2)) + "%), BGP num: " + str(0) + " (" + str(round(0 / len(data_bgp) * 100, 2)) + "%), total ROA num: " + str(num_valid + num_valid_cross + num_valid_org + num_invalid_cross + num_invalid_org + num_unknown_notexist) + " (" + str(round((num_valid + num_valid_cross + num_valid_org + num_invalid_cross + num_invalid_org + num_unknown_notexist) / len(data_roa) * 100, 2)) + "%), total BGP num: " + str(bgp_num_valid + bgp_num_valid_cross + bgp_num_valid_org + bgp_num_invalid_cross + bgp_num_invalid_org) + " (" + str(round((bgp_num_valid + bgp_num_valid_cross+ bgp_num_valid_org + bgp_num_invalid_cross + bgp_num_invalid_org) / len(data_bgp) * 100, 2)) + "%)")
    print("=====Coverage of FRO=====")
    coverage(data_FRO, False)

def write_FRO(data_FRO, new_f):
    f1 = open(new_f, 'w')
    for key, item in data_FRO.items():
        asn = key[1]
        prefix = key[0]
        maxLength = key[2]
        source = item['source']
        confidence = item['confidence']
        f1.write("{ \"asn\": \"AS" + str(asn) + "\", \"prefix\": \"" + prefix + "\", \"maxLength\": " + str(maxLength) + ", \"source\": [ { \"type\": \"roa\", \"uri\": \"" + source + "\", \"tal\": \"" + str(confidence) + "\", \"validity\": { \"notBefore\": \"\", \"\": \"\" }, \"chainValidity\": { \"notBefore\": \"\", \"notAfter\": \"\" } }]}\n")
    f1.close()

def write_bgp(data, new_f):
    f1 = open(new_f, 'w')
    for key, item in data.items():
        asn = key[1]
        prefix = key[0]
        num = item['num']
        valid = item['valid']
        invalid = item['invalid']
        valid_str = ''
        invalid_str = ''
        for i in range(len(valid)):
            valid_str += ' [' + valid[i][0] + ' ' + str(valid[i][1]) + ' ' + str(valid[i][2]) + ']'
        for i in range(len(invalid)):
            invalid_str += ' [' + invalid[i][0] + ' ' + str(invalid[i][1]) + ' ' + str(invalid[i][2]) + ']'
        f1.write("\"asn\": " + str(asn) + ", \"prefix\": " + prefix + ", \"num\": " + str(num) + ", \"valid\": " + valid_str + ", \"invalid\": " + invalid_str + "\n")
    f1.close()

def write_irr(data, new_f):
    f1 = open(new_f, 'w')
    for key, item in data.items():
        asn = key[1]
        prefix = key[0]
        num = item['num']
        valid = item['valid']
        invalid = item['invalid']
        valid_str = ''
        invalid_str = ''
        for i in range(len(valid)):
            valid_str += ' [' + valid[i][0] + ' ' + str(valid[i][1]) + ']'
        for i in range(len(invalid)):
            invalid_str += ' [' + invalid[i][0] + ' ' + str(invalid[i][1]) + ']'
        f1.write("\"asn\": " + str(asn) + ", \"prefix\": " + prefix + ", \"num\": " + str(num) + ", \"valid\": " + valid_str + ", \"invalid\": " + invalid_str + "\n")
    f1.close()


def write_roa(data, new_f):
    f1 = open(new_f, 'w')
    for key, item in data.items():
        asn = key[1]
        prefix = key[0]
        num = item['num']
        valid = item['valid']
        invalid = item['invalid']
        initial = item['initial']
        initial_prefix = item['initial-prefix']
        valid_str = ''
        invalid_str = ''
        for i in range(len(valid)):
            valid_str += ' [' + valid[i][0] + ' ' + str(valid[i][1])+ ']'
        for i in range(len(invalid)):
            invalid_str += ' [' + invalid[i][0] + ' ' + str(invalid[i][1])+ ']'
        
        initial_prefix_str = ''
        for temp in initial_prefix:
            initial_prefix_str += ' [' + temp[0] + ' ' + str(temp[1]) + ' ' + str(temp[2]) + ']'

        f1.write("\"asn\": " + str(asn) + ", \"prefix\": " + prefix + ", \"num\": " + str(num) + ", \"valid\": " + valid_str + ", \"invalid\": " + invalid_str + ", \"initial\": " + str(initial) + ", \"initial_prefix\": " + initial_prefix_str + "\n")
    f1.close()


def analyze_iviv(data_bgp, data_roa, data_FRO, file):
    f = open(file, 'r')
    data = {}
    for line in f:
        prefix = line.split(' ')[0]
        asn = int(line.split(' ')[1].split('\n')[0])
        data[(prefix, asn)] = {}
        data[(prefix, asn)]['status'] = 'invalid'
        data[(prefix, asn)]['reason'] = []
        print(prefix, asn, data_bgp[(prefix, asn)])
        if len(data_bgp[(prefix, asn)]['valid']) > 0:
            for temp in data_bgp[(prefix, asn)]['valid']:
                key = (temp[0], temp[1], temp[2])
                if key in data_FRO:
                    data[(prefix, asn)]['status'] = 'valid'
                    data[(prefix, asn)]['reason'].append(data_FRO[key]['source'])
        
        if len(data_bgp[(prefix, asn)]['invalid']) > 0:
            for temp in data_bgp[(prefix, asn)]['invalid']:
                key = (temp[0], temp[1], temp[2])
                if key in data_FRO:
                    data[(prefix, asn)]['status'] = 'valid'
                    data[(prefix, asn)]['reason'].append(data_FRO[key]['source'])
    num = 0
    for key, item in data.items():
        #print(key, item)
        if item['status'] == 'valid':
            num += 1
    print(len(data), num)




if __name__ == '__main__':

    start_time = time.time()

    #step 1: construct source map
    data_bgp = {}
    data_roa = {}

    #A BGP dictionary specially for IRR
    data_bgp_irr = {}
    data_irr = {}

    spemap_v4 = {}
    spemap_v6 = {}

    getspemap(spemap_v4, spemap_v6, private_ip_list_v4, private_ip_list_v6)
    process_bgp('sources/rib_total-json-20230909.json', data_bgp, spemap_v4, spemap_v6)
    process_bgp('sources/rib_total-json-20230909.json', data_bgp_irr, spemap_v4, spemap_v6)
    #process_bgp('sources/updates_total-json-20230909.json')
    #process_bgp('sources/total-json-20230909.json')

    
    
    #data_bgp_irr = {k: v for k, v in data_bgp.items()}
    process_roa('sources/0909', data_roa, spemap_v4, spemap_v6)
    process_roa_aggregate('sources/0909_aggregate', data_roa, spemap_v4, spemap_v6)
    process_irr('sources/irr-route-total', data_irr, spemap_v4, spemap_v6)
    process_irr('sources/irr-route6-total', data_irr, spemap_v4, spemap_v6)
    '''
    prefix_list = []
    for key in data_roa:
        if key[1] == 0:
            prefix_list.append(key[0])
    print("Done!", len(prefix_list))
    for key in data_irr:
        if key[0] in prefix_list and key[1] != 0:
            print(key) 
    '''
    asrel_v4 = {}
    asrel_cus_v4 = {}
    asrel_v6 = {}
    asrel_cus_v6 = {}
    process_asrel('20230901.as-rel.txt', asrel_v4, asrel_cus_v4)
    process_asrel('20230901.as-rel.v6-stable.txt', asrel_v6, asrel_cus_v6)
    #print(checkASc2p(1299, 25091, asrel_v4, asrel_cus_v4))
    #print(checkASc2p(1299, 8298, asrel_v4, asrel_cus_v4))
    #print(checkASc2p(31025, 20562, asrel_v4, asrel_cus_v4))

    
    dic_asncsv = {}
    dic_asname = {}
    dic_orgid = {}
    dic_asn = {}
    process_asn2n(dic_asncsv, dic_asname, dic_orgid, dic_asn)

    #print(data_irr[('42.115.115.0/24', 18403, 32)])
    #print(data_roa[('42.115.115.0/24', 18403, 32)])
    print("=====Coverage of RIB=====")
    unused_networks_ipv4, used_networks_ipv6 = coverage(data_bgp, True)
    '''
    print("=====Coverage of RPKI ROA=====")
    coverage(data_roa, False)
    print("=====Coverage of IRR=====")
    coverage(data_irr, False)
    '''
    roamap_v4 = {}
    roamap_v6 = {}
    getroamap(roamap_v4, roamap_v6, data_roa)
    print(rovproc(roamap_v6, getpfxbin('2400:a980:1000::', 40), 40, 133517, '2400:a980:1000::/40', data_bgp, data_roa))
    print(data_bgp[('2400:a980:1000::/40', 133517)])

    execution_time = time.time() - start_time
    print("Time, process time is " + str(int(execution_time)) + "s")
    
    #step 2: conduct rov
    rov(data_bgp, data_roa, spemap_v4, spemap_v6, dic_asn)
    print("End rov")
    #rov(data_bgp_irr, data_irr, spemap_v4, spemap_v6, dic_asn)
    #print("End rov")
    
    execution_time = time.time() - start_time
    print("Time, rov time is " + str(int(execution_time)) + "s")
    
    '''
    #write data_bgp, data_irr, data_roa to file
    write_bgp(data_bgp, 'FRO/data_bgp')
    write_irr(data_irr, 'FRO/data_irr')
    write_roa(data_roa, 'FRO/data_roa')
    '''
    '''
    compare_time(data_bgp, data_roa)
    '''
    

    
    #step 3: construct FRO
    data_FRO = {}
    construct_FRO(data_bgp, data_roa, data_FRO, asrel_v4, asrel_v6, dic_asn, data_bgp_irr, data_irr, unused_networks_ipv4, used_networks_ipv6)
    
    write_FRO(data_FRO, 'FRO/results')

    execution_time = time.time() - start_time
    print("Time, FRO time is " + str(int(execution_time)) + "s")

    '''
    num = 0
    num_invalid = 0
    for key, item in data_bgp.items():
        if len(item['valid']) == 1:
            temp = (item['valid'][0][0], item['valid'][0][1], item['valid'][0][2])
            if data_roa[temp]['initial'] == False:
                print("=====" + str(num) + "=====")
                print(key, item['valid'], "initial: ", data_roa[temp]['initial-prefix'])
                flag = 0
                temp_list = item['invalid']
                for temp1 in temp_list:
                    temp2 = (temp1[0], temp1[1], temp1[2])
                    if temp2 not in data_roa[temp]['initial-prefix']:
                        print('invalid', temp2)
                        flag = 1
                if flag == 1:
                    num_invalid += 1
                num += 1
    print(num, num_invalid)
    '''
    
    analyze_iviv(data_bgp, data_roa, data_FRO, 'iv_iv_RIB_TOTAL-CN')
    execution_time = time.time() - start_time
    print("Time, analyze time is " + str(int(execution_time)) + "s")
    