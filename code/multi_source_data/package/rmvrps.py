#! /usr/bin/python2

import sys


repo = set()
r2 = set()
cmpf = sys.argv[-1]



for fp in sys.argv[1:-1]:
    fin = open(fp, 'r')
    for line in fin:
        line = line.strip().split(',')
        uri = line[0]
        asn = line[1]
        pfx = line[2]
        maxlen = line[3]
        repo.add(','.join(line[1:4]))
    fin.close()

fin = open(cmpf, 'r')
for line in fin:
    line = line.strip()
    line = line.strip().split(',')
    uri = line[0]
    asn = line[1]
    pfx = line[2]
    r2.add(','.join(line[1:4]))


print len(repo)
print len(r2)

for e in repo:
    if e not in r2:
        print e

