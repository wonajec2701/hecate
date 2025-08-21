#!/usr/bin/env python
import sys
import time


def intas(asn):
    if '.' not in asn:
        try:
            rel = int(asn)
            return rel
        except:
            return 0
    asn = asn.split('.')
    rel = long(int(asn[0])*65536 + int(asn[1]))
    return rel

def ReadLinkOfMonitors(file, mons):
    linkset = set()
    f = open(file, 'r')
    for line in f:
        if '#' in line:
            continue
        line = line.strip().split()
        if len(line) < 2:
            continue
        if line[0] == 'M':
            continue
        as1 = int(line[0])
        as2 = int(line[1])
        if as1 in mons or as2 in mons:
            if as1 > as2:
                link = (as2, as1)
            else:
                link = (as1, as2)
            linkset.add(link)

    return linkset

def ReadMonitors(file):
    mons = set()
    f = open(file, 'r')
    for line in f:
        line = line.strip().split()
        if line[0] != '':
            mons.add(int(line[0]))
    
    return mons


def ReadLinks(file):
    linkset = set()
    f = open(file, 'r')
    for line in f:
        if line[0] == '#':
            continue
        line = line.strip().split()
        if len(line) < 2:
            continue
        as1 = intas(line[0])
        as2 = intas(line[1])
        #ISOTIMEFORMAT ='%Y-%m-%d %X'
        #st = time.strftime(ISOTIMEFORMAT, time.gmtime(int(line[2])))
        #et = time.strftime(ISOTIMEFORMAT, time.gmtime(int(line[3])))
        #print as1, as2, st, et
        #link = (as1, as2)
        if as1 > as2:
            link = (as2, as1)
        else:
            link = (as1, as2)
        linkset.add(link)
    return linkset

def ReadRelations(file):
    linkset = dict()
    f = open(file, 'r')
    for line in f:
        line = line.strip().split()
        if len(line) < 3:
            continue
        #if line[2] == '-':
        #    continue
        
        as1 = line[0]
        as2 = line[1]
        link = (as1, as2)
        type = line[2]

        linkset[link] = type

    return linkset


