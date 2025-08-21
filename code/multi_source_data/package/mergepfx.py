#! /usr/bin/python2

import sys


def readpfx(pfxmap, fn):
    fin = open(fn, 'r')
    for line in fin:
        line = line.strip().split()
        pfx = line[0]
        asns = line[1:]
        if pfx not in pfxmap:
            pfxmap[pfx] = set()
        s = pfxmap[pfx]
        for asn in asns:
            s.add(asn)
    fin.close()



pfxmap = {}

fns = sys.argv[1:]
for fn in fns:
    readpfx(pfxmap, fn)

for pfx in pfxmap:
    asnstr = ' '.join(list(pfxmap[pfx]))
    print pfx, asnstr

