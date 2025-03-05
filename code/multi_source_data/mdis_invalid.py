#!/usr/bin/env python
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
#import bgpdump
from datetime import datetime, timedelta
from operator import inv
from typing import List

from tqdm import tqdm
#current_directory = os.getcwd()
current_directory = sys.argv[1]
increment = int(sys.argv[2])
content = sys.argv[3]

def is_ip_range_covered(range1, range2):
    try:
        net1 = ipaddress.ip_network(range1)
        net2 = ipaddress.ip_network(range2)
    except ValueError:
        with open(f"{current_directory}/bgp_route/run-log/runlog",'a') as log:
            log.write(f"{range1,range2} there is an ValueError"+"\n")
        match1 = re.match(r'(.*)\n',range1)
        match2 = re.match(r'(.*)\n',range2)
        if match1:
            range1 = match1.group(1)
        if match2:
            range2 = match2.group(1)
        net1 = ipaddress.ip_network(range1)
        net2 = ipaddress.ip_network(range2)
    if net1.version!=net2.version:
        return False
    if net1.supernet_of(net2):
        return True
    else:
        return False
    

def main():

    start_time = datetime.now()
    start_timetamp = start_time.strftime("%Y%m%d %H:%M:%S")
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        if increment == 0:
            log.write(f"{content}: {start_timetamp} mdis_invalid.py started\n")
        else:
            log.write(f"{content}: {start_timetamp} incremental mdis_invalid.py started\n")


    now=datetime.now()-timedelta(hours=8)
    
    check_timestamp=now.strftime("%Y%m%d")
    year = current_directory.split('-')[0]
    month = current_directory.split('-')[1]
    day = current_directory.split('-')[2]
    check_timestamp = year+month+day
    print(check_timestamp)
    if increment == 0:
        invalid_output=f'{current_directory}/bgp_route/checklog/invalid/mdis_invalid-output-{check_timestamp}_{content}.json'
        valid_output=f'{current_directory}/bgp_route/checklog/valid/mdis_valid-output-{check_timestamp}_{content}.json'
        unknown_output=f'{current_directory}/bgp_route/checklog/unknown/mdis_unknown-output-{check_timestamp}_{content}.json'
    elif increment == 1:
        invalid_output=f'{current_directory}/bgp_route/checklog/invalid/increment_mdis_invalid-output-{check_timestamp}_{content}.json'
        valid_output=f'{current_directory}/bgp_route/checklog/valid/increment_mdis_valid-output-{check_timestamp}_{content}.json'
        unknown_output=f'{current_directory}/bgp_route/checklog/unknown/increment_mdis_unknown-output-{check_timestamp}_{content}.json'
    elif increment == 2:
        invalid_output=f'{current_directory}/bgp_route/checklog/invalid/add-mdis_invalid-output-{check_timestamp}_{content}.json'
        valid_output=f'{current_directory}/bgp_route/checklog/valid/add-mdis_valid-output-{check_timestamp}_{content}.json'
        unknown_output=f'{current_directory}/bgp_route/checklog/unknown/add-mdis_unknown-output-{check_timestamp}_{content}.json'
    
    if not os.path.exists(os.path.dirname(invalid_output)):
        os.makedirs(os.path.dirname(invalid_output))
    if not os.path.exists(os.path.dirname(valid_output)):
        os.makedirs(os.path.dirname(valid_output))
    if not os.path.exists(os.path.dirname(unknown_output)):
        os.makedirs(os.path.dirname(unknown_output))
    
    if increment == 0:
        validity_json=f'{current_directory}/bgp_route/checklog/total/mdis_validity-total-{check_timestamp}_{content}.json'
        invalid_asn_prefix_output=f'{current_directory}/bgp_route/checklog/invalid/mdis_invalid-asn_prefix-output-{check_timestamp}_{content}.txt'
        valid_asn_prefix_output=f'{current_directory}/bgp_route/checklog/valid/mdis_valid-asn_prefix-output-{check_timestamp}_{content}.txt'
        unknown_asn_prefix_output=f'{current_directory}/bgp_route/checklog/unknown/mdis_unknown-asn_prefix-output-{check_timestamp}_{content}.txt'
    elif increment == 1:
        validity_json=f'{current_directory}/bgp_route/checklog/total/increment-mdis_validity-total-{check_timestamp}_{content}.json'
        invalid_asn_prefix_output=f'{current_directory}/bgp_route/checklog/invalid/increment-mdis_invalid-asn_prefix-output-{check_timestamp}_{content}.txt'
        valid_asn_prefix_output=f'{current_directory}/bgp_route/checklog/valid/increment-mdis_valid-asn_prefix-output-{check_timestamp}_{content}.txt'
        unknown_asn_prefix_output=f'{current_directory}/bgp_route/checklog/unknown/increment-mdis_unknown-asn_prefix-output-{check_timestamp}_{content}.txt'
    elif increment == 2:
        validity_json=f'{current_directory}/bgp_route/checklog/total/add-mdis_validity-total-{check_timestamp}_{content}.json'
        invalid_asn_prefix_output=f'{current_directory}/bgp_route/checklog/invalid/add-mdis_invalid-asn_prefix-output-{check_timestamp}_{content}.txt'
        valid_asn_prefix_output=f'{current_directory}/bgp_route/checklog/valid/add-mdis_valid-asn_prefix-output-{check_timestamp}_{content}.txt'
        unknown_asn_prefix_output=f'{current_directory}/bgp_route/checklog/unknown/add-mdis_unknown-asn_prefix-output-{check_timestamp}_{content}.txt'
    
    asn_org=f'CAIDA/as_org/as-org2info.txt'

    printer_json={"validated_routes": []}
    printer_json_valid={"validated_routes": []}
    printer_json_unknown={"validated_routes": []}

    asn_list=[]
    prefix_list=[]
    invalid_list=[]
    invalid_type_list=[]

    asn_list_valid=[]
    prefix_list_valid=[]
    valid_list=[]

    asn_list_unknown=[]
    prefix_list_unknown=[]
    unknown_list=[]
    #---------------------------------------
    with open(validity_json,'r') as input, open(asn_org,'r') as as_name:
        json_data=json.load(input)
        progress_bar = tqdm(json_data['validated_routes'], desc=f'validity-json', unit='route', unit_scale=True, leave=True,file=sys.stdout)
        for json_entry in json_data['validated_routes'] :
            progress_bar.update(1)
            if json_entry['validity']['state']=='invalid':
                asn_list.append(json_entry['route']['origin_asn'])
                prefix_list.append(json_entry['route']['prefix'])
                invalid_type_list.append(json_entry['validity']['reason'])
                printer_json['validated_routes'].append(json_entry)
            if json_entry['validity']['state']=='valid':
                asn_list_valid.append(json_entry['route']['origin_asn'])
                prefix_list_valid.append(json_entry['route']['prefix'])
                printer_json_valid['validated_routes'].append(json_entry)
            if json_entry['validity']['state']=='unknown':
                asn_list_unknown.append(json_entry['route']['origin_asn'])
                prefix_list_unknown.append(json_entry['route']['prefix'])
                printer_json_unknown['validated_routes'].append(json_entry)
        #print(asn_list_unknown)
        print("as_org_list")
        as_org_list=[0]*401500
        data_lines=as_name.readlines()
        start_line="aut|changed|aut_name|org_id|opaque_id|source"
        start_flag=0
        for line in data_lines:
            if start_flag==1:
                nums=list(line.split("|"))
                as_org_list[int(nums[0])]=nums[2]
                #print(nums[2])
                continue
            if start_line in line:
                start_flag=1
                #print(line)
                continue
        #====invalid_list
        print("invalid_list")
        try:
            for i in range(0,len(asn_list)):
                match=re.match(r'AS(.*)',asn_list[i])
                if match:
                    if int(match.group(1))>401309:
                        #print(int(match.group(1)))
                        invalid_list.append(f"{asn_list[i]} {prefix_list[i]} {invalid_type_list[i]}"+" Private Use AS")
                        continue
                    invalid_list.append(f"{asn_list[i]} {prefix_list[i]} {invalid_type_list[i]} {as_org_list[int(match.group(1))]}")
        except IndexError:
            print(i)
            print(asn_list[i])
            print(prefix_list[i])
            print(invalid_type_list[i])
            print(as_org_list[int(match.group(1))])
            sys.exit(0)
        print("invalid_list finished！")
        with open(invalid_output,'w') as output_json, open (invalid_asn_prefix_output,'w') as output_asn_prefix:
            printer=json.dumps(printer_json)
            output_json.write(printer)
            for item in invalid_list:
                output_asn_prefix.write(item+'\n')
            #output_asn_prefix.write(f"{invalid_list}")
            print(f"invalid(ASN,prefix)，{invalid_asn_prefix_output},{invalid_output}")

        #====valid_list
        print("valid_list")
        for i in range(0,len(asn_list_valid)):
            match=re.match(r'AS(.*)',asn_list_valid[i])
            if match:
                if int(match.group(1))>401309:
                    #print(int(match.group(1)))
                    valid_list.append(f"{asn_list_valid[i]} {prefix_list_valid[i]}"+" Private Use AS")
                    continue
                valid_list.append(f"{asn_list_valid[i]} {prefix_list_valid[i]} {as_org_list[int(match.group(1))]}")
        print("valid_list finished！")
        with open(valid_output,'w') as output_json, open (valid_asn_prefix_output,'w') as output_asn_prefix:
            printer=json.dumps(printer_json_valid)
            output_json.write(printer)
            for item in valid_list:
                output_asn_prefix.write(item+'\n')
            #output_asn_prefix.write(f"{valid_list}")
            print(f"valid(ASN,prefix)，{valid_asn_prefix_output},{valid_output}")

        #====unknown_list
        print("unknown_list")
        for i in range(0,len(asn_list_unknown)):
            match=re.match(r'AS(.*)',asn_list_unknown[i])
            if match:
                if int(match.group(1))>401309:
                    #print(int(match.group(1)))
                    valid_list.append(f"{asn_list_unknown[i]} {prefix_list_unknown[i]}"+" Private Use AS")
                    continue
                unknown_list.append(f"{asn_list_unknown[i]} {prefix_list_unknown[i]} {as_org_list[int(match.group(1))]}")
        print("unknown finished！")
        with open(unknown_output,'w') as output_json, open (unknown_asn_prefix_output,'w') as output_asn_prefix:
            printer=json.dumps(printer_json_unknown)
            output_json.write(printer)
            for item in unknown_list:
                output_asn_prefix.write(item+'\n')
            #output_asn_prefix.write(f"{valid_list}")
            print(f"unknown(ASN,prefix)，{unknown_asn_prefix_output},{unknown_output}")

    with open(f"{current_directory}/bgp_route/run-log/log-{check_timestamp}",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        if increment == 0:
            log.write(f"{finish_timestamp} invalid.py！"+"\n")      
        else:
            log.write(f"{finish_timestamp} incremental invalid.py！"+"\n")      

    with open(f"{current_directory}/execution_log.txt",'a') as log:
        duration = finish_time - start_time
        if increment == 0:
            log.write(f"{content}: {finish_timestamp} mdis_invalid.py ended, used {duration}\n")
        else:
            log.write(f"{content}: {finish_timestamp} incremental mdis_invalid.py ended, used {duration}\n")
        





if __name__ == '__main__':
    main()
