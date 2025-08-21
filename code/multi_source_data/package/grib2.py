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
            if filelist != []:
                for fn in filelist:
                    if datestr in fn:
                        fn = path+'/'+fn
                        fs.append(fn)
    return fs

paths = []
cmd = sys.argv[1]
datestr = sys.argv[2]
paths.append(sys.argv[3])
outfile = sys.argv[-1]
fns = getfiles(paths, datestr)

if len(fns) > 0:
    infs = ' '.join(fns)
    cmdstr = "%s %s > %s " % (cmd, infs, outfile)
    print cmdstr
    os.system(cmdstr)
print 'finished...', datestr

