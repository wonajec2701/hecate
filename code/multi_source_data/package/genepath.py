import os

def excmd(cn, datepfx, s, t, dr, opf):
    i = s
    while i<= t:
        ds = f'{cn} {datepfx}{i:02} {dr} {opf}{i:02}'
        i+=1
        print(ds)
        os.system(ds)


cmdname = "python2 ../grib.py ../getaspath.py \" bgpdump -m\" "
dr = "/ldc/data/ripe202209/ribs/" 
#dr = "/ldc/data/ripe202209/ribs/"
excmd(cmdname, '202209',1, 7, dr, 'ripe.pfx.202209')
#excmd(cmdname, '202002',29, dr, 'ripe202002')

