#! /usr/bin/python2

import sys


repo = set()
r2 = set()
cmpf = sys.argv[-1]


def readroa(roamap, fp):
    fin = open(fp, 'r')
    for line in fin:
        line = line.strip().split(',')
        asn = line[1][2:]
        pfx = line[2]
        if ':' not in pfx:
            if pfx not in roamap:
                roamap[pfx] = asn

roamaps = {}
fns = sys.argv[1:]
n = len(sys.argv[1:])
k = 0
allpfx = set()
for fp in fns:
    roamaps[k] = {}
    readroa(roamaps[k], fp)
    r = roamaps[k]
    for p in r:
        allpfx.add(p)
    k = k + 1

m = {}
for p in allpfx:
    m[p] = []
    for i in range(n):
        if p in roamaps[i]:
            m[p].insert(i, roamaps[i][p])
        else:
            m[p].insert(i, '')


for p in m:
    print p, m[p]





