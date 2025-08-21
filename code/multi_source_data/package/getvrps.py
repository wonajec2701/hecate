#! /usr/bin/python2

import sys


for fp in sys.argv[1:]:
    fin = open(fp, 'r')
    for line in fin:
        line = line.strip()
        if 'Before' in line:
            continue
        print line
    fin.close()


