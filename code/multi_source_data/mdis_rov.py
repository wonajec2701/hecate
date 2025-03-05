#!/usr/bin/env python
from datetime import datetime, timedelta
import json
import os
import subprocess
import sys
import time

from tqdm import tqdm

from package import mio, pfxrov

#current_directory = os.getcwd()
current_directory = sys.argv[1]
increment = int(sys.argv[2])
content = sys.argv[3]
#

def checkspeasn(asns):
    try:
        asn = int(list(asns)[0])
    except:
        asn = int(asns)
    if asn == 0 or 64496 <= asn <= 131071 or 401309 <= asn <= 4294967295 or asn == 23456 or 153914 <= asn <= 196607 or 216476 <= asn <= 262143 or 274845 <= asn <= 327679 or 329728 <= asn <= 393215:
        return True
    else:
        return False

def get_ts(tmstr):
    timearr = time.strptime(tmstr, "%Y-%m-%dT%H:%M:%SZ")
    tm = int(time.mktime(timearr))
    return tm


def getroamap(roamap4,roamap6, fn):
    with open(fn, 'r') as f:
        lines = f.readlines()
    progress_bar = tqdm(lines, desc=f'getroamap', unit='line', unit_scale=True, leave=True,file=sys.stdout)
    for line in lines:
        progress_bar.update(1)
        if 'asn' not in line:
            continue
        line = line.strip().split('ource')
        roa = line[0].replace(', "s',"}")#{ "asn": "AS13335", "prefix": "1.0.0.0/24", "maxLength": 24}
        #print(roa)
        asn = roa.split('"')[3][2:]
        pfx = roa.split('"')[7]
        maxlen = roa.split('"')[10].replace(": ","").replace("}","")
        line = line[1].split('{')[2].split('"')
        #st = get_ts(line[3])
        st = line[3]
        #et = get_ts(line[7])
        et = line[7]
        if '.' in pfx:
            pfxrov.createROAmap(roamap4, roa, asn, pfx, maxlen, st, et)
        if ":" in pfx:
            pfxrov.createROAmap6(roamap6, roa, asn, pfx, maxlen, st, et)

def getpfxmap(pfxmap4,pfxmap6,fn):
    with open(fn, 'r') as f:
        data_json = json.load(f)
        route_json=data_json["routes"]
    progress_bar = tqdm(route_json, desc=f'getpfxmap', unit='line', unit_scale=True, leave=True,file=sys.stdout)
    route_dict={}
    for route in route_json:
        progress_bar.update(1)
        pfx = route["prefix"]
        asns = route["asn"]
        if pfx in route_dict:
            if asns in route_dict[pfx]:
                continue
            values=route_dict[pfx]
            values.append(asns)
            route_dict[pfx]=values
        else:
            values=[]
            values.append(asns)
            route_dict[pfx]=values
    
    progress_bar = tqdm(route_dict.items(), desc=f'getpfxmap', unit='line', unit_scale=True, leave=True,file=sys.stdout)
    for pfx,asns in route_dict.items():
        progress_bar.update(1)
        asns=set(asns)
        if ':' not in pfx:
            pfxrov.createpfxmap(pfxmap4, asns, pfx)
        if ':' in pfx:
            pfxrov.createpfxmap6(pfxmap6, asns, pfx)

def getspemap(spemap4,spemap6, spelist):
    progress_bar = tqdm(spelist, desc=f'getpfxmap', unit='line', unit_scale=True, leave=True,file=sys.stdout)
    for pfx in spelist:
        progress_bar.update(1)
        asns = []
        """ for IPv4 routes """
        if ':' not in pfx:
            pfxrov.createpfxmap(spemap4, asns, pfx)
        if ':' in pfx:
            pfxrov.createpfxmap6(spemap6, asns, pfx)


def checkspepfx(spemap, pfx, length):
    pfx_exists = False
    for pl in range(length, -1, -1):
        if pl not in spemap:
            continue
        t = pfx[:pl]
        if t in spemap[pl]:
            pfx_exists = True
            return pfx_exists
    return pfx_exists

""" route orgin validation based on ROAs """
def rovproc(roamap, pfx, length, asnset, pfxstr, validty_file,type,rov_json):#pfx：pfxmap[length][pfxbin]=(asns,prefix)
    with open(validty_file, 'a') as validty:
        asnset=set(asnset)
        pfx_exists = False
        for origin_as in asnset:
            rov_entry_json={"route": {
            "origin_asn": "AS0",
            "prefix": "0.0.0.0/0"
            },
            "validity": {
            "state": "null",
            "reason": "null",
            "VRPs": {
                "matched": [
                ],
                "unmatched_as": [
                ],
                "unmatched_length": [
                ],
                "both_unmatched": [
                ]
                }
            }}
            valid_flag=False
            length_flag=False
            as_flag=False
            valid_vrps=set()
            length_vrps=set()
            as_vrps=set()
            for pl in range(length, -1, -1):
                if pl not in roamap:
                    continue
                t = pfx[:pl]
                if t in roamap[pl]:
                    pfx_exists = True
                    vrpset = roamap[pl][t]
                    n = vrpset['num']
                    vrps = vrpset['vrps']
                    for i in range(n):
                        v = vrps[i]
                        maxlen = v['maxlen']
                        asn = int(v['asn'])
                        #print(type(asn))
                        if length <= maxlen and asn == origin_as :
                            valid_flag=True
                            valid_vrps.add(f"{v['ip']}/{pl} {maxlen}")
                            vrp={}
                            vrp["asn"]=f"AS{asn}"
                            vrp["prefix"]=f"{v['ip']}/{pl}"
                            vrp["max_length"]=f"{maxlen}"
                            rov_entry_json["validity"]["VRPs"]["matched"].append(vrp)
                        elif length > maxlen and asn == origin_as:
                            length_vrps.add(f"{v['ip']}/{pl} {maxlen}")
                            vrp={}
                            vrp["asn"]=f"AS{asn}"
                            vrp["prefix"]=f"{v['ip']}/{pl}"
                            vrp["max_length"]=f"{maxlen}"
                            if rov_entry_json["validity"]["reason"]=="null":
                                rov_entry_json["validity"]["reason"]="length"
                            rov_entry_json["validity"]["VRPs"]["unmatched_length"].append(vrp)
                        elif length > maxlen and asn != origin_as:
                            length_vrps.add(f"{v['ip']}/{pl} {maxlen}")
                            vrp={}
                            vrp["asn"]=f"AS{asn}"
                            vrp["prefix"]=f"{v['ip']}/{pl}"
                            vrp["max_length"]=f"{maxlen}"
                            if rov_entry_json["validity"]["reason"]!="as":
                                rov_entry_json["validity"]["reason"]="both"
                            rov_entry_json["validity"]["VRPs"]["both_unmatched"].append(vrp)
                        elif length <= maxlen and asn != origin_as:
                            as_vrps.add(f"{v['ip']}/{pl} {maxlen}")
                            vrp={}
                            vrp["asn"]=f"AS{asn}"
                            vrp["prefix"]=f"{v['ip']}/{pl}"
                            vrp["max_length"]=f"{maxlen}"
                            rov_entry_json["validity"]["reason"]="as"
                            rov_entry_json["validity"]["VRPs"]["unmatched_as"].append(vrp)
            rov_entry_json["route"]["origin_asn"]=f"AS{origin_as}"
            rov_entry_json["route"]["prefix"]=pfxstr
            if valid_flag:
                r = "%s %s" % (origin_as,'valid ')
                rov_entry_json["validity"]["state"]="valid"
                validty.write(f"{pfxstr} {r} "+"\n")
            elif pfx_exists:
                r = "%s %s" % (origin_as,'invalid')
                rov_entry_json["validity"]["state"]="invalid"
                validty.write(f"{pfxstr} {r}"+"\n")
            elif not pfx_exists:
                r = "%s %s" % (origin_as,'unknown')     
                validty.write(f"{pfxstr} {r}"+"\n")
                rov_entry_json["validity"]["state"]="unknown"
            rov_json["validated_routes"].append(rov_entry_json)
        #validty.write(f"-----"+"\n")

def main():
    start_time = datetime.now()
    start_timetamp = start_time.strftime("%Y%m%d %H:%M:%S")
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        if increment == 0:
            log.write(f"{content}: {start_timetamp} mdis rov started\n")
        else:
            log.write(f"{content}: {start_timetamp} incremental mdis rov started\n")

    print("....")
    now = datetime.now()-timedelta(hours=8)
    timestamp = now.strftime("%Y%m%d")
    print(f"{timestamp}")
    year = current_directory.split('-')[0]
    month = current_directory.split('-')[1]
    day = current_directory.split('-')[2]
    timestamp = year+month+day
    print(f"{timestamp}")
    
    if increment == 0:
        if content == 'None':
            roa_file=f"{current_directory}/cro_data/cro_retification_{current_directory}"
        else:
            roa_file=f"{current_directory}/cro_data/cro_retification_{current_directory}_{content}"
        route_file=f"{current_directory}/bgp_route/checklog/total/total-json-{timestamp}.json"
        validty_file=f"{current_directory}/bgp_route/checklog/total/mdis_validity-total-{timestamp}-rov-simple_{content}"
        rov_json_file=f"{current_directory}/bgp_route/checklog/total/mdis_validity-total-{timestamp}_{content}.json"
    elif increment == 1:
        roa_file=f"{current_directory}/cro_data/cro_retification_{current_directory}_{content}"
        route_file=f"{current_directory}/bgp_route/checklog/total/total-json-{timestamp}.json"
        validty_file=f"{current_directory}/bgp_route/checklog/total/increment-mdis_validity-total-{timestamp}-rov-simple_{content}"
        rov_json_file=f"{current_directory}/bgp_route/checklog/total/increment-mdis_validity-total-{timestamp}_{content}.json"
    elif increment == 2:
        roa_file=f"{current_directory}/cro_data/cro_retification_{current_directory}_{content}"
        route_file=f"{current_directory}/bgp_route/checklog/total/add-total-json-{timestamp}_{content}.json"
        validty_file=f"{current_directory}/bgp_route/checklog/total/add-mdis_validity-total-{timestamp}-rov-simple_{content}"
        rov_json_file=f"{current_directory}/bgp_route/checklog/total/add-mdis_validity-total-{timestamp}_{content}.json"
    log_file=f"{current_directory}/bgp_route/run-log/log-{timestamp}"
    roamap4 = {}
    roamap6 = {}
    pfxmap4 = {}
    pfxmap6 = {}
    spemap4 = {}
    spemap6 = {}
    
    
    rov_json={"validated_routes": []}
    cmd= f"rm -f {validty_file}"
    subprocess.check_output(cmd, shell=True, universal_newlines=True) 
    getroamap(roamap4 , roamap6, roa_file)
    getpfxmap(pfxmap4 , pfxmap6, route_file)
    getspemap(spemap4 , spemap6, pfxrov.special_pfx_list)
    
    
    #sys.exit(0)
    for pl in range(32, -1, -1):
        type=4
        if pl not in pfxmap4:
            continue
        #if pl > 24:
        #    continue
        pfxs = pfxmap4[pl]
        progress_bar = tqdm(pfxs, desc=f'pfxs4-{pl}', unit='line', unit_scale=True, leave=True,file=sys.stdout)
        for pfx in pfxs:
            progress_bar.update(1)
            if checkspepfx(spemap4, pfx, pl)==True:
                continue
            #print(pfx,pl)
            asns = pfxs[pfx]['asns']
            if checkspeasn(list(asns)[0]) == True:
                continue
            pfxstr = pfxs[pfx]['prefix']#pfxs：pfxmap[length] pfx:[pfxbin]
            rovproc(roamap4, pfx, pl, asns , pfxstr , validty_file,type,rov_json)
    for pl in range(128, -1, -1):
        type=6
        if pl not in pfxmap6:
            continue
        #if pl > 24:
        #    continue
        pfxs = pfxmap6[pl]
        progress_bar = tqdm(pfxs, desc=f'pfxs6-{pl}', unit='line', unit_scale=True, leave=True,file=sys.stdout)
        for pfx in pfxs:
            progress_bar.update(1)
            if checkspepfx(spemap6, pfx, pl)==True:
                continue
            #print(pfx,pl)
            asns = pfxs[pfx]['asns']
            if checkspeasn(list(asns)[0]) == True:
                continue
            pfxstr = pfxs[pfx]['prefix']#pfxs：pfxmap[length] pfx:[pfxbin]
            rovproc(roamap6, pfx, pl, asns , pfxstr , validty_file,type,rov_json)



    with open(rov_json_file,'w') as rov_output:
        rov_output.write(json.dumps(rov_json))
    with open(validty_file, 'r') as rov:
        lines=rov.readlines()
        
    count_lines=0
    count_valid=0
    count_invalid=0
    count_unknown=0
    #rov_lines
    progress_bar = tqdm(lines, desc=f'rov-lines', unit='line', unit_scale=True, leave=True,file=sys.stdout)
    for line in lines:
        count_lines+=1
        progress_bar.update(1)
        nums=line.split()
        status = nums[2]
        if status == "valid":
            count_valid +=1
        elif status == "invalid":
            count_invalid +=1
        elif status == "unknown":
            count_unknown +=1  

    print(f"count_invalid={count_invalid} count_unknown={count_unknown} count_valid={count_valid}")
    print(f"count_invalid={(count_invalid/count_lines)*100:.2f}% count_unknown={(count_unknown/count_lines)*100:.2f}% count_valid={(count_valid/count_lines)*100:.2f}%")
    with open(log_file, 'a') as rov_log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        if increment == 0:
            rov_log.write(f"{finish_timestamp} mdis rov"+"\n")
        else:
            rov_log.write(f"{finish_timestamp} incremental mdis rov"+"\n")
        rov_log.write(f"{content}: count_invalid={count_invalid} count_unknown={count_unknown} count_valid={count_valid}"+"\n")
        rov_log.write(f"{content}: count_invalid={(count_invalid/count_lines)*100:.2f}% count_unknown={(count_unknown/count_lines)*100:.2f}% count_valid={(count_valid/count_lines)*100:.2f}%"+"\n")

    with open(f"{current_directory}/execution_log.txt",'a') as log:
        duration = finish_time - start_time
        if increment == 0:
            log.write(f"{finish_timestamp} mdis rov ended, used {duration}\n")
        else:
            log.write(f"{finish_timestamp} incremental mdis rov ended, used {duration}\n")
        log.write(f"{content}: count_invalid={count_invalid} count_unknown={count_unknown} count_valid={count_valid}"+"\n")
        log.write(f"{content}: count_invalid={(count_invalid/count_lines)*100:.2f}% count_unknown={(count_unknown/count_lines)*100:.2f}% count_valid={(count_valid/count_lines)*100:.2f}%"+"\n")





if __name__ == '__main__':
    main()