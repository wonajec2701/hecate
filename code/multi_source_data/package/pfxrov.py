import sys
import ipaddress

map = {}
mapbin = {}


special_pfx_list = [
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
        '255.255.255.255/32',
        "fc00::/7","2001::/23","fe80::/10","2001:db8::/32","2001:2::/48","100::/64","64:ff9b:1::/48","::ffff:0:0/96","::/128","::1/128","2001:10::/28"
        ]

def getpfxbin(pfx, length):
    pfxbinstr = ''
    """ IPv4 prefix """
    if ':' not in pfx:
        pfx = pfx.split('.')
        for seg in pfx:
            segstr = bin(int(seg))[2:].zfill(8)
            pfxbinstr += segstr
    """ IPv6 prefix """
    if ':' in pfx:
        pfxint=int(ipaddress.IPv6Address(pfx))
        pfxbinstr=bin(pfxint)[2:]
        pfxbinstr='0'*(128-len(pfxbinstr))+pfxbinstr
        """ 
        pfx = pfx.split(':')
        pfxbinlist = []i = 0
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
        pfxbinstr = ''.join(pfxbinlist) """
    return pfxbinstr[:length]


def readmap(filename):
    global map
    global mapbin
    f = open(filename, 'r')
    for line in f:
        if '|' in line:
            line = line.strip().split('|')
            pfx = line[0]
            ases = line[1].split()
        else:
            line = line.strip().split()
            pfx = line[0]
            ases = line[1:]
        if '/' not in pfx:
            print ('prefix format error')
            continue
        if pfx not in map:
            map[pfx] = set()
        for asn in ases:
            map[pfx].add(asn)

def readpfxset(filename):
    pfxset = set()
    f = open(filename, 'r')
    for line in f:
        line = line.strip().split()
        pfxset.add(line[0])
    return pfxset

    

def initmapbin():
    for pfxstr in map:
        pfx = pfxstr.split('/')
        ip = pfx[0]
        length = int(pfx[1])
        if length not in mapbin:
            mapbin[length] = {}
        pfxbin = getpfxbin(ip, length)
        mapbin[length][pfxbin] = pfxstr



def getpfxfromip(ipaddr):
    pfx = '-1'
    if '.' in ipaddr:
        ipbin = getpfxbin(ipaddr, 128)
        for i in range(128, -1, -1):
            t = ipbin[:i]
            if i in mapbin and t in mapbin[i]:
                    pfx = mapbin[i][t]
                    break
    return pfx

""" Create a set of ROAs stored in map structure """
def createROAmap(roamap, roa, asn, pfxstr, maxlen, st, et):
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
    p['roa'] = roa
    p['vrp'] = pfxstr
    p['asn'] = asn
    p['maxlen'] = int(maxlen)
    p['st'] = st
    p['et'] = et
    p['ip'] = ip
    r['num'] = k + 1

def createROAmap6(roamap, roa, asn, pfxstr, maxlen, st, et):
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
    p['roa'] = roa
    p['vrp'] = pfxstr
    p['asn'] = asn
    p['maxlen'] = int(maxlen)
    p['st'] = st
    p['et'] = et
    p['ip'] = ip
    r['num'] = k + 1
        
""" Create a map of prefix-to-origin from BGP annnoucements """ 
def createpfxmap(pfxmap, asns, pfxstr):
    pfx = pfxstr.split('/')
    ip = pfx[0]
    length = int(pfx[1])
    if length not in pfxmap:
        pfxmap[length] = {}
    pfxbin = getpfxbin(ip, length)
    pfxmap[length][pfxbin] = {}
    s = pfxmap[length][pfxbin]
    s['prefix'] = pfxstr
    a = s['asns'] = set()
    for asn in asns:
        a.add(asn)

def createpfxmap6(pfxmap, asns, pfxstr):
    
    pfx = pfxstr.split('/')
    ip = pfx[0]
    length = int(pfx[1])
    if length not in pfxmap:
        pfxmap[length] = {}
    pfxbin = getpfxbin(ip, length)
    pfxmap[length][pfxbin] = {}
    s = pfxmap[length][pfxbin]
    s['prefix'] = pfxstr
    a = s['asns'] = set()
    for asn in asns:
        a.add(asn)

def searchpfx(pfxmapbin, ipaddr):
    pfx = 'nonexist'
    if '.' in ipaddr:
        ipbin = getpfxbin(ipaddr, 32)
        for i in range(32, -1, -1):
            t = ipbin[:i]
            if i in pfxmapbin and t in pfxmapbin[i]:
                    pfx = pfxmapbin[i][t]
                    break
    if ':' in ipaddr:
        ipbin = getpfxbin(ipaddr, 128)
        for i in range(128, -1, -1):
            t = ipbin[:i]
            if i in pfxmapbin and t in pfxmapbin[i]:
                    pfx = pfxmapbin[i][t]
                    break
    return pfx

def getasfromip(ipaddr):
    pfx = getpfxfromip(ipaddr)
    if pfx == '-1':
        return '-1'
    else:
        asnlist = list(map[pfx])
        return ','.join(asnlist)

def getasfrompfx(pfx):
    if pfx == '':
        return '-1'
    else:
        asnlist = list(map[pfx])
        return ','.join(asnlist)

def checkip2pfxmatch(ipaddr, pfxstr):
    if '/' not in pfxstr:
        print ('prefix format error')
        return False
    pfx = pfxstr.split('/')
    ip = pfx[0]
    length = int(pfx[1])
    pfxbin = getpfxbin(ip, length)
    ipaddrbin = getpfxbin(ipaddr, length)
    if pfxbin == ipaddrbin:
        return True
    else:
        return False

def mapinsert(pfx, asns):
    """ insert new item with prefix and a mapped list of asns"""
    if pfx not in map:
        map[pfx] = set()
    for asn in asns:
        map[pfx].add(asn)

def mapappend(pfx, asn):
    if pfx in map:
        map[pfx].add(asn)

def mapset(pfx, asn):
    map[pfx] = set()
    map[pfx].add(asn)


def mapdelete(pfx, asn):
    if pfx in map and asn in map[pfx]:
        map[pfx].remove(asn)

def clearmap():
    map.clear()

def printmap(filename):
    f = open(filename, 'w')
    for pfx in map:
        asns = ' '.join(list(map[pfx]))
        outstr = '%s %s\n' % (pfx, asns)
        f.write(outstr)

