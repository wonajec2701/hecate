#! /usr/bin/python2

import sys
import os


tool = sys.argv[1]
para = sys.argv[2]

dupf = {}

for fn in sys.argv[3:]:
    cmdstr = "{} {} {}".format(tool, para, fn)
    fp = os.popen(cmdstr)
    for line in fp:
        line = line.strip().split('|')
        tm = line[1]
        peerip = line[3]
        pfx = line[5]
        aspath = line[6]
        collector = (peerip, aspath.split()[0])
        if collector not in dupf:
            dupf[collector] = {}
        if pfx not in dupf[collector]:
            dupf[collector][pfx] = set()
        if aspath not in dupf[collector][pfx]:
            dupf[collector][pfx].add(aspath)
            print tm, pfx, peerip, aspath

