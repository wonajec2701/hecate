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
roafile = sys.argv[1]
bgpfile = sys.argv[2]
roamap = {}
pfxmap = {}
spemap = {}

#getroamap_routinator(roamap, roafile)
getroamap(roamap, roafile)
getpfxmap(pfxmap, bgpfile)
getspemap(spemap, pfxrov.special_pfx_list)




"""route validation"""
for pl in range(32, -1, -1):
    if pl not in pfxmap:
        continue
    #if pl > 24:
    #    continue
    pfxs = pfxmap[pl]
    for pfx in pfxs:
        if checkspepfx(spemap, pfx, pl)==True:
            continue
        asns = pfxs[pfx]['asns']
        pfxstr = pfxs[pfx]['prefix']
        r = rovproc(roamap, pfx, pl, asns)
        print pfxstr, asns, r        



