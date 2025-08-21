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
import mio

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




""" Main programm """
bgpdump = sys.argv[1]
para = sys.argv[2]


originMap = {}
routes = {}
files = sys.argv[3:]
for fn in files:
    cmdstr = "{} {} {}".format(bgpdump, para, fn)
    f = os.popen(cmdstr)
    for line in f:
        line = line.strip().split('|')
        if len(line) < 3:
            continue
        tm = line[1]
        pfx = line[5]
        aspath = line[6].split()
        origin = aspath[-1]
	origin_asset = ''
        """This is a test"""
        if origin == []:
            print 'empty'
        orgleft = ''
        if '{' not in origin:
            orgtmp = origin
            """
            i = 2
            length = len(aspath)
            while private_asn(orgtmp) and i <= length:
                #print orgtmp
                orgtmp = aspath[-i]
                i += 1
            if orgtmp != origin:
                origin = orgtmp+'-'+origin
                #origin = orgtmp
            """
        else:
            """ deal with AS set """
	    origin_asset = origin
            """
            orgset = set()
            asset = origin_asset[1:-1].split(',')
            for asn in asset:
                if not private_asn(asn):
                    orgset.add(asn)
            """
            """ search for the last ASN that is not in AS-set and not a private ASN """
            asseq = aspath[:-1]
            seqlen = len(asseq)
            if seqlen > 0:
                i = 1
                orgleft = asseq[-1]
                while private_asn(orgleft) and i <= seqlen:
                    orgleft =asseq[-i]
                    i += 1
                if not private_asn(orgleft):
                    origin = orgleft

        if pfx not in originMap:
            originMap[pfx] = {}
            routes[pfx] = set()
        if origin not in originMap[pfx]:
            originMap[pfx][origin] = 0
        originMap[pfx][origin] += 1
	if origin_asset != '':
	    if origin_asset not in originMap[pfx]:
		originMap[pfx][origin_asset] = 0
	    originMap[pfx][origin_asset] += 1


org = {}
orgset = {}
rel = {}
for prefix in originMap:
    org.clear()
    orgset.clear()
    rel.clear()
    OriginASNs = originMap[prefix].keys()
    for item in OriginASNs:
        if '{' not in item:
            if item not in org:
                org[item] = 0
            org[item] += originMap[prefix][item]
        else:
            asset = item[1:-1].split(',')
            for asn in asset:
                if not private_asn(asn):
		    asn = '*'+asn
                    if asn not in orgset:
                        orgset[asn] = 0
                    orgset[asn] += originMap[prefix][item]
    for asn in org:
	if asn not in rel:
            rel[asn] = 0
        rel[asn] += org[asn]

    if len(orgset) > 0:
        for asn in orgset:
            if asn not in rel:
                rel[asn] = 0
            rel[asn] += orgset[asn]

    addr = pfx.split('/')[0]
    if addr == '0.0.0.0':
        continue

    print prefix, 
    for asn in rel:
        print asn,
    print ''

