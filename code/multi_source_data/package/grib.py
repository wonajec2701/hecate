#! /usr/bin/env python

#########################################
#
# usage, for example
# grib.py cmd "parameters" 20140914 ~/mdata/rv-201409/ribs/route-views.saop/ ll
#
##########################################

import sys
import os

def getfiles(paths, datestr):
    fs = []
    for p in paths:
        e = os.walk(p)
        for path, dirlist, filelist in e:
            if dirlist == []:
                for fn in filelist:
                    if datestr in fn:
                        fn = path+'/'+fn
                        fs.append(fn)
    return fs

paths = []
cmd = sys.argv[1]
para = sys.argv[2]
datestr = sys.argv[3]
paths.append(sys.argv[4])
outfile = sys.argv[-1]
fns = getfiles(paths, datestr)

if len(fns) > 0:
    infs = ' '.join(fns)
    cmdstr = "%s %s %s > %s " % (cmd, para, infs, outfile)
    print cmdstr
    os.system(cmdstr)
print 'finished...', datestr

