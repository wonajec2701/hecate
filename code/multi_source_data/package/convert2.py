#! /usr/bin/python2

import sys


for fp in sys.argv[1:]:
    fin = open(fp, 'r')
    for line in fin:
        line = line.strip()
        s = line.split()
        pfx = s[0]
        asns = s[1:]
        for asn in asns:
            if '*' in asn or '-' in asn:
                continue
            theasn = asn
        if '.' in pfx:
            out = "%s => %s" % (pfx, theasn)
            print out
    fin.close()


