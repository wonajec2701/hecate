import os

def excmd(cn, datepfx, s, t, dr, opf):
    i = s
    while i<= t:
        j = 0
        while j < 24:
            ds = f'{cn} {datepfx}{i:02}.{j:02}00 {dr} {opf}{i:02}.{j:02}00'
            j+=2
            print(ds)
            os.system(ds)
        i+=1


cmdname = "python2 ../grib.py ../GetPfxOrgMap.py \" bgpdump -m\" "
dr = "/ldc/data/rv202209/ribs/" 
#dr = "/ldc/data/ripe202209/ribs/"
excmd(cmdname, '202209',1, 7, dr, 'pfx.rv.202209')
#excmd(cmdname, '202002',29, dr, 'ripe202002')

