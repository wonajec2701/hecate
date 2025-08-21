#! /usr/bin/python2

import sys


repo = set()
r2 = set()
cmpf = sys.argv[-1]



for fp in sys.argv[1:-1]:
    fin = open(fp, 'r')
    for line in fin:
        line = line.strip().split()
        repo.add(line[0])
    fin.close()

fin = open(cmpf, 'r')
for line in fin:
    line = line.strip().split()
    r2.add(line[0])


print len(repo)
print len(r2)


for e in r2:
    if e not in repo:
        print e

