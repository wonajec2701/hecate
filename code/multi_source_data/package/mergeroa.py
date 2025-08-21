import os

def excmd(cn, datepfx, s, t, dr, opf):
    i = s
    while i<= t:
        ds = f'{cn} {datepfx}{i:02} {dr} {opf}{i:02}'
        i+=1
        print(ds)
        os.system(ds)


cmdname = "python2 ../grib2.py ../getvrps.py"
dr = "/ldd/rpki-roa/" 
excmd(cmdname, '202301',1, 31, dr, 'rir-roas.202301')
#dr = "/ldc/data/ripe202002/ribs/"
#excmd(cmdname, '202002',29, dr, 'ripe202002')

