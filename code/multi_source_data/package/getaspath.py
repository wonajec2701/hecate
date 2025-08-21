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


pathmap = {}
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
        aspath = line[6]
        key = "%s|%s" % (pfx, aspath)
        if key not in pathmap:
            pathmap[key] = tm


for aspath in pathmap:
    tm = pathmap[aspath]
    aspath = aspath.split('|')
    pfx = aspath[0]
    path = aspath[1]
    print tm, pfx, path
