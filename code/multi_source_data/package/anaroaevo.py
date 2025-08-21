#! /usr/bin/env python
##########################################
#
# This program has been upgraded. it gives 
# the final correct orgin AS for each prefix
#
#
# Please run this program, not that with no "run" prefix
# input is "rawBGPpaths"
#
# checked on Nov 2, 2011
#
# refined by May 28, 2013
#
# refined by July 14, 2019
#
#
############################################
import os
import copy
import sys
import pfxrov
import time

def private_asn(asnstr):
    try:
        asn = mio.intas(asnstr)
    except:
        print asnstr
    if asn == 0 or asn == 23456 or (asn >= 64496 and asn <=131071) \
            or asn >=4200000000: 
        return True
    else:
        return False



def get_ts(tmstr):
    timearr = time.strptime(tmstr, "%Y-%m-%d %H:%M:%S")
    tm = int(time.mktime(timearr))
    return tm


def getroamap(roamap, fn):
    f = open(fn)
    for line in f:
        if 'Before' in line:
            continue
        line = line.strip().split(',')
        roa = line[0]
        asn = line[1][2:]
        pfx = line[2]
        maxlen = line[3]
        st = get_ts(line[4])
        et = get_ts(line[5])
        """ for IPv4 ROA """
        if '.' in pfx:
            pfxrov.createROAmap(roamap, roa, asn, pfx, maxlen, st, et)
    f.close()

def getroamap_routinator(roamap, fn):
    f = open(fn)
    for line in f:
        if 'ASN' in line:
            continue
        line = line.strip().split(',')
        asn = line[0][2:]
        pfx = line[1]
        maxlen = line[2]
        st = 0
        et = 0
        """ for IPv4 ROA """
        if ':' not in pfx:
            pfxrov.createROAmap(roamap, asn, pfx, maxlen, st, et)
    f.close()

def getpfxmap(pfxmap, fn):
    f = open(fn)
    for line in f:
        line = line.strip().split()
        pfx = line[0]
        asns = line[1:]
        """ for IPv4 routes """
        if ':' not in pfx:
            pfxrov.createpfxmap(pfxmap, asns, pfx)
    f.close()


def readvrps(roaset, fn):
    f = open(fn)
    for line in f:
        line = line.strip().split(',')
        roauri = line[0]
        asn = line[1]
        pfx = line[2]
        maxlen = line[3]
        if roauri not in roaset:
            roaset[roauri] = set()
        e = ','.join(line[0:3])
        roaset[roauri].add(e)

def getspemap(spemap, spelist):
    for pfx in spelist:
        asns = []
        """ for IPv4 routes """
        if ':' not in pfx:
            pfxrov.createpfxmap(spemap, asns, pfx)

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

""" route orgin validation based on ROAs """
def rovproc(roamap, pfx, length, asnset):
    r = 'unknown'
    pfx_exists = False
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
                if length <= maxlen and asn in asnset:
                    r = "%s %s %s %s" % ('valid ', v['vrp'], maxlen, asn)
                    return r

    if pfx_exists:
        r = 'invalid'

    return r




""" Main programm """
roaf1 = sys.argv[1]
roaf2 = sys.argv[2]
roamap1 = {}
roamap2 = {}
roaset1 = {}
roaset2 = {}
#getroamap_routinator(roamap, roafile)
#getroamap(roa1, roaf1)
#getroamap(roa2, roaf2)
readvrps(roaset1, roaf1)
readvrps(roaset2, roaf2)




"""roa analysis"""

birthroa = {}
deathroa = {}

roa1as = set()
roa2as = set()
bas = set()
das = set()



for uri in roaset1:
    p = roaset1[uri]
    for e in p:
        t = e.split(',')
        asn = t[1]
        roa1as.add(asn)


for uri in roaset2:
    p = roaset2[uri]
    for e in p:
        t = e.split(',')
        asn = t[1]
        roa2as.add(asn)


for uri in roaset2:
    if uri not in roaset1:
        birthroa[uri] = roaset2[uri]
    else:
        p = roaset2[uri]
        q = roaset1[uri]
        for e in p:
            if e not in q:
                t = e.split(',')
                asn = t[1]
                bas.add(asn)
                if uri not in birthroa:
                    birthroa[uri] = set()
                birthroa[uri].add(e)


for uri in roaset1:
    if uri not in roaset2:
        deathroa[uri] = roaset1[uri]
    else:
        p = roaset1[uri]
        q = roaset2[uri]
        for e in p:
            if e not in q:
                print e
                t = e.split(',')
                asn = t[1]
                das.add(asn)
                if uri not in deathroa:
                    deathroa[uri] = set()
                deathroa[uri].add(e)


print len(birthroa)
print len(deathroa)
print len(roa1as)
print len(roa2as)
print len(bas)
print len(das)



"""
for uri in birthroa:
    vrps = birthroa[uri]
    for e in vrps:
        if '::' not in e:
            pass
            #print e


for uri in deathroa:
    vrps = deathroa[uri]
    for e in vrps:
        if '::' not in e:
            print e
"""

"""
for pl in range(32, -1, -1):
    if pl not in roa2:
        continue
    pfxs = roa2[pl]
    for pfxbin in pfxs:
        r = roa2[pl][pfxbin]

    for pfx in pfxs:
        if checkspepfx(spemap, pfx, pl)==True:
            continue
        asns = pfxs[pfx]['asns']
        pfxstr = pfxs[pfx]['prefix']
        r = rovproc(roamap, pfx, pl, asns)
        print pfxstr, asns, r        
"""


