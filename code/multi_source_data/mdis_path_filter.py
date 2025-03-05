#!/usr/bin/env python
import gc
import ipaddress
import json
import multiprocessing
import os
import pickle
import re
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from datetime import datetime, timedelta
from email.errors import FirstHeaderLineIsContinuationDefect
from multiprocessing.sharedctypes import Value
from sqlite3 import Timestamp
from typing import List

import matplotlib.pyplot as plt
import numpy as np
from scipy.interpolate import interp1d
from tqdm import tqdm
#current_directory = os.getcwd()
current_directory = sys.argv[1]
increment = int(sys.argv[2])
content = sys.argv[3]

def find_smallest_including_range(ip_range1, ip_range2):
    try:
        network1 = ipaddress.ip_network(ip_range1, strict=False)
        network2 = ipaddress.ip_network(ip_range2, strict=False)
    except ValueError:
        with open(f"{current_directory}/bgp_route/run-log/runlog",'a') as log:
                log.write(f"{ip_range1,ip_range2} there is an ValueError"+"\n")
        match1 = re.match(r'(.*)\n',ip_range1)
        match2 = re.match(r'(.*)\n',ip_range2)
        if match1:
            ip_range1 = match1.group(1)
        if match2:
            ip_range2 = match2.group(1)
        network1 = ipaddress.ip_network(ip_range1)
        network2 = ipaddress.ip_network(ip_range2)
        
    min_network = min(network1, network2)
    max_network = max(network1, network2)
    
    smallest_including_range = min_network.supernet(new_prefix=min_network.prefixlen - 1)
    return smallest_including_range


def as_analysis(invalid_asn_prefix_file,asn_org,invalid_as_file,as_org_list):
    with open (invalid_asn_prefix_file,'r') as invalid_asn_prefix, open(invalid_as_file,'w') as invalid_as:

        #============invalid_asn_freq
        print("invalid_asn_freq")
        invalid_asn=[]
        invalid_asn_freq=[0]*401500
        private_as_org_freq=[]
        private_as_org_record=[]
        invalid_asn_sum=0
        for invalid_route in invalid_asn_prefix:
            invalid_asn_sum+=1
            match=re.match(r'AS(\d{1,11}) (\d+\.\d+\.\d+\.\d+/\d+) (.*)',invalid_route)
            if not match:
                match = re.match(r"AS(\d{1,11}) (.*/\d{1,3}) (.*)",invalid_route)
            invalid_asn.append(int(match.group(1)))
            if int(match.group(1))>401309:
                if int(match.group(1)) not in private_as_org_record:
                    #print(int(match.group(1)))
                    invalid_asn_freq_private={
                                    "count":0,
                                    "asn":"AS0"}
                    invalid_asn_freq_private["asn"]=int(match.group(1))
                    invalid_asn_freq_private["count"]=1
                    private_as_org_record.append(int(match.group(1)))
                    private_as_org_freq.append(invalid_asn_freq_private)
                    #print(private_as_org_record)
                    #print(private_as_org_freq)
                else :
                    for item in private_as_org_freq:
                        if item["asn"]==int(match.group(1)):
                            item["count"]+=1
            else :
                #print(int(match.group(1)))
                invalid_asn_freq[int(match.group(1))]+=1
                #print(invalid_asn_freq[int(match.group(1))])
        invalid_asn=list(set(invalid_asn))
        invalid_as.write(f"{invalid_asn}")
        print("invalid_asn_freq")
        #print(invalid_asn_freq[21656])
        invalid_asn_freq_top = sorted(range(len(invalid_asn_freq)), key=lambda k: invalid_asn_freq[k], reverse=True)
        
        
        #===================
        for i in range (0,len(invalid_asn_freq)):
            if invalid_asn_sum:
                invalid_asn_freq[i]=int((invalid_asn_freq[i]/invalid_asn_sum)*100)
            else:
                invalid_asn_freq[i]=0
        count_private_as=0
        for item in private_as_org_freq:
            count_private_as+=1
            item["count"]=item["count"]/invalid_asn_sum
        

def sub_process(file_name,processid,timestamp,invalid_as_file):
    if increment == 0:
        invalid_as_path_chunk_file=f"{current_directory}/bgp_route/analysis/path/mdis_invalid_as_path-{timestamp}-{processid}_{content}"
        total_as_path_chunk_file=f"{current_directory}/bgp_route/analysis/path/mdis_total_as_path-{timestamp}-{processid}_{content}"
    elif increment == 2:
        invalid_as_path_chunk_file=f"{current_directory}/bgp_route/analysis/path/add-mdis_invalid_as_path-{timestamp}-{processid}_{content}"
        total_as_path_chunk_file=f"{current_directory}/bgp_route/analysis/path/add-mdis_total_as_path-{timestamp}-{processid}_{content}"
    if not os.path.exists(os.path.dirname(invalid_as_path_chunk_file)):
        os.makedirs(os.path.dirname(invalid_as_path_chunk_file))
    with open(invalid_as_file,'r') as invalid_as,open(invalid_as_path_chunk_file,'w') as invalid_as_path_chunk,open (total_as_path_chunk_file,'wb') as total_as_path_chunk:
        invalid_as_list=invalid_as.readline()
        total_as_path_json={}
        progress_bar = tqdm(file_name, desc=f'Processing:{processid}', unit='line', unit_scale=True, leave=True,file=sys.stdout)
        
        for line in file_name:
            progress_bar.update(1)
            item=line.split(' ')
            if item[0] in invalid_as_list:
                invalid_as_path_chunk.write(f"{line}")
            #print(f"{type(item[0])}{type(item[1])}    {item[2:]}")
            route_asn=item[0]
            route_prefix=item[1]
            if route_asn in total_as_path_json:
                route_list = total_as_path_json[route_asn]
                route_list.add(route_prefix)
                total_as_path_json[route_asn]=route_list 
            else:
                route_list=set()
                route_list.add(route_prefix)
                total_as_path_json[route_asn]=route_list 
            #print(total_as_path_json[item[0],item[1]])
        pickle.dump(total_as_path_json,total_as_path_chunk)
        

    

def path_filter(invalid_as_file,total_rib_as_path_input_file,invalid_as_path_file,timestamp,total_bview_as_path_input_file,total_as_path_json_file,total_pch_as_path_input_file):
    num_of_chunk=20
    processid = 1
    #rib
    print(total_rib_as_path_input_file)
    with open(total_rib_as_path_input_file,'r') as total_as_path_input:
        #read_seq=0  
        lines=total_as_path_input.readlines()
    num_lines=len(lines)
    lines_per_process = num_lines // num_of_chunk
    print(f"{num_lines}")
    print(f"{lines_per_process}")
    remainder = num_lines % num_of_chunk  #  
    print(f"{remainder}")
    file_chunks = [lines[i:i+lines_per_process] for i in range(0, num_lines, lines_per_process)]
    ts=[]
    del lines
    gc.collect()
    for chunk in file_chunks:
        # ，
        t = multiprocessing.Process(target=sub_process, args=(chunk,processid,timestamp,invalid_as_file))
        ts.append(t)
        # 
        t.start()   
        processid=processid+1
    for i in ts:
        i.join()
    print(f"All processs finished.")
    del file_chunks
    gc.collect()


    #bview
    with open(total_bview_as_path_input_file,'r') as total_as_path_input:
        #read_seq=0  
        lines=total_as_path_input.readlines()
    num_lines=len(lines)
    lines_per_process = num_lines // num_of_chunk
    print(f"{num_lines}")
    print(f"{lines_per_process}")
    remainder = num_lines % num_of_chunk  #  
    print(f"{remainder}")
    file_chunks = [lines[i:i+lines_per_process] for i in range(0, num_lines, lines_per_process)]
    ts=[]
    del lines
    gc.collect()
    for chunk in file_chunks:
        # ，
        t = multiprocessing.Process(target=sub_process, args=(chunk,processid,timestamp,invalid_as_file))
        ts.append(t)
        # 
        t.start()   
        processid=processid+1
    for i in ts:
        i.join()
    print(f"All processs finished.")
    del file_chunks
    gc.collect()
    #pch    
    try:
        with open(total_pch_as_path_input_file,'r') as total_as_path_input:
            #read_seq=0  
            lines=total_as_path_input.readlines()
        num_lines=len(lines)
        lines_per_process = num_lines // num_of_chunk
        print(f"{num_lines}")
        print(f"{lines_per_process}")
        remainder = num_lines % num_of_chunk  #  
        print(f"{remainder}")
        file_chunks = [lines[i:i+lines_per_process] for i in range(0, num_lines, lines_per_process)]
        ts=[]
        del lines
        gc.collect()
        for chunk in file_chunks:
            # ，
            t = multiprocessing.Process(target=sub_process, args=(chunk,processid,timestamp,invalid_as_file))
            ts.append(t)
            # 
            t.start()   
            processid=processid+1
        for i in ts:
            i.join()
   
        print(f"All processs finished.")
        del file_chunks
        gc.collect()
    except:
        pass
    
        
    with open(invalid_as_path_file,'w') as invalid_as_path:
        print("invalid_as_path...")
        list_total=[]
        list_temp=[]
        for processid in range(1,processid+2):
            if increment == 0:
                filename_list_to_check=f"{current_directory}/bgp_route/analysis/path/mdis_invalid_as_path-{timestamp}-{processid}_{content}"
            elif increment == 2:
                filename_list_to_check=f"{current_directory}/bgp_route/analysis/path/add-mdis_invalid_as_path-{timestamp}-{processid}_{content}"
            #print(f"{filename_list_to_check}")
            if os.path.exists(filename_list_to_check):
                print(f"{filename_list_to_check}")
                with open(filename_list_to_check,'r') as list_file:
                    #print(f"{list_file.readlines()}"+"/n")
                    list_temp=list_file.readline()
                    while list_temp:
                        #print(list_temp)
                        """ list_total.append(list_temp.strip())
                        size_control+=1 """
                        invalid_as_path.write(f"{list_temp.strip()}" +"\n")
                        list_temp=list_file.readline()
            else :
                    print(f"{filename_list_to_check}")
    with open(total_as_path_json_file,'wb') as total_as_path_json:
        print("total_as_path_json...")
        total_routes_dict={}
        for processid in range(1,processid+2):
            if increment == 0:
                filename_list_to_check=f"{current_directory}/bgp_route/analysis/path/mdis_total_as_path-{timestamp}-{processid}_{content}"
            elif increment == 2:
                filename_list_to_check=f"{current_directory}/bgp_route/analysis/path/add-mdis_total_as_path-{timestamp}-{processid}_{content}"
            #print(f"{filename_list_to_check}")
            if os.path.exists(filename_list_to_check) and os.path.getsize(filename_list_to_check) > 0:
                print(f"{filename_list_to_check}")
                with open(filename_list_to_check,'rb') as route_file:
                    route_dict = pickle.load(route_file)
                    for asn in route_dict:
                        if asn in total_routes_dict:
                            route_set=route_dict[asn]
                            total_routes_set=total_routes_dict[asn]
                            total_routes_set=set(route_set).union(set(total_routes_set))
                            total_routes_dict[asn]=total_routes_set
                        else:
                            total_routes_dict[asn]=route_dict[asn]
            else :
                    print(f"{filename_list_to_check}")
        pickle.dump(total_routes_dict, total_as_path_json)
    if increment == 0:
        cmd3=f"rm -f {current_directory}/bgp_route/analysis/path/mdis_invalid_as_path*{timestamp}*"
        cmdoutput = subprocess.check_output(cmd3, shell=True, universal_newlines=True)
        cmd3=f"rm -f {current_directory}/bgp_route/analysis/path/mdis_total_as_path*{timestamp}*"
        cmdoutput = subprocess.check_output(cmd3, shell=True, universal_newlines=True)
    elif increment == 2:
        cmd3=f"rm -f {current_directory}/bgp_route/analysis/path/add-mdis_invalid_as_path*{timestamp}*"
        cmdoutput = subprocess.check_output(cmd3, shell=True, universal_newlines=True)
        cmd3=f"rm -f {current_directory}/bgp_route/analysis/path/add-mdis_total_as_path*{timestamp}*"
        cmdoutput = subprocess.check_output(cmd3, shell=True, universal_newlines=True)


def main():
    start_time = datetime.now()
    start_timetamp = start_time.strftime("%Y%m%d %H:%M:%S")
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        if increment == 0:
            log.write(f"{content}: {start_timetamp} mdis path filter started\n")
        else:
            log.write(f"{content}: {start_timetamp} incremental mdis path filter started\n")

    print("....")
    now = datetime.now()-timedelta(hours=8)
    
    timestamp=now.strftime("%Y%m%d")
    roa_timestamp=now.strftime("%m%d")
    #timestamp="20231007"
    #roa_timestamp="1007"
    year = current_directory.split('-')[0]
    month = current_directory.split('-')[1]
    day = current_directory.split('-')[2]
    timestamp = year+month+day
    roa_timestamp = timestamp
    print(f"{timestamp}")


    analysis_time=time.time()
    #=================
    if increment == 0:
        invalid_asn_prefix_file=f"{current_directory}/bgp_route/checklog/invalid/mdis_invalid-asn_prefix-output-{timestamp}_{content}.txt"
        total_rib_as_path_input_file = f"{current_directory}/bgp_route/path/rib-total-path-{timestamp}"
        total_bview_as_path_input_file = f"{current_directory}/bgp_route/path/bview-total-path-{timestamp}"
        total_pch_as_path_input_file=f"{current_directory}/bgp_route/path/pch-total-path-{timestamp}"
        
        total_as_path_json_file = f"{current_directory}/bgp_route/path/mdis_total-path-json-{timestamp}_{content}"
        #-------------------------
        invalid_as_file=f"{current_directory}/bgp_route/analysis/invalid/mdis_invalid_as-{timestamp}_{content}"
        invalid_as_path_file=f"{current_directory}/bgp_route/analysis/invalid/mdis_invalid_as_path-{timestamp}_{content}"
    
    elif increment == 2:
        invalid_asn_prefix_file=f"{current_directory}/bgp_route/checklog/invalid/add-mdis_invalid-asn_prefix-output-{timestamp}_{content}.txt"
        total_rib_as_path_input_file = f"{current_directory}/bgp_route/path/rib-total-path-{timestamp}"
        total_bview_as_path_input_file = f"{current_directory}/bgp_route/path/bview-total-path-{timestamp}"
        total_pch_as_path_input_file=f"{current_directory}/bgp_route/path/pch-total-path-{timestamp}"
        
        total_as_path_json_file = f"{current_directory}/bgp_route/path/add-mdis_total-path-json-{timestamp}_{content}"
        #-------------------------        
        invalid_as_file=f"{current_directory}/bgp_route/analysis/invalid/add-mdis_invalid_as-{timestamp}_{content}"
        invalid_as_path_file=f"{current_directory}/bgp_route/analysis/invalid/add-mdis_invalid_as_path-{timestamp}_{content}"

    if not os.path.exists(os.path.dirname(invalid_as_file)):
        os.makedirs(os.path.dirname(invalid_as_file))


    

    
    #return
    #============as_org_list
    asn_org=f'CAIDA/as_org/as-org2info.txt'
    as_org_list=[0]*401500
    with open(asn_org,'r') as as_name:
        print("as_org_list")
        data_lines=as_name.readlines()
        start_line="aut|changed|aut_name|org_id|opaque_id|source"
        nation_line="format:org_id|changed|org_name|country|source"
        nation_flag=0
        start_flag=0
        id_name_dict={}
        for line in data_lines:
            if (nation_line not in line and nation_flag==0):
                #print(line)
                continue
            nation_flag=1
            if start_line in line:
                start_flag=1
                #print(line)
                continue
            if start_flag==0:
                nums=list(line.split("|"))
                org_id=nums[0]
                org_name=nums[2].lower()
                id_name_dict[org_id]=org_name
            elif start_flag==1:
                nums=list(line.split("|"))
                asn=int(nums[0])
                org_id=nums[3]
                as_org_list[asn]=id_name_dict[org_id]
                #print(asn)
    #===============
    
    as_analysis(invalid_asn_prefix_file,asn_org,invalid_as_file,as_org_list)
    as_analysis_time=time.time() 
    print("as_analysis，："+time.strftime("%H:%M:%S", time.gmtime(as_analysis_time-analysis_time)))
    
    path_filter(invalid_as_file,total_rib_as_path_input_file,invalid_as_path_file,timestamp,total_bview_as_path_input_file,total_as_path_json_file,total_pch_as_path_input_file)
    #path_filter2(invalid_as_file,total_as_path_input_file,invalid_as_path_file)
    path_filter_time=time.time()
    print("path_filter，："+time.strftime("%H:%M:%S", time.gmtime(path_filter_time-as_analysis_time)))
    

    
    
    
    analysis_end_time=time.time()
    with open(f"{current_directory}/bgp_route/run-log/log-{timestamp}",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        log.write(f"{finish_timestamp} path_filter，："+time.strftime("%H:%M:%S", time.gmtime(analysis_end_time-analysis_time))+"\n")
    print("path_filter，："+time.strftime("%H:%M:%S", time.gmtime(analysis_end_time-analysis_time)))

    with open(f"{current_directory}/execution_log.txt",'a') as log:
        duration = finish_time - start_time
        if increment == 0:
            log.write(f"{content}: {finish_timestamp} mdis path filter ended, used {duration}\n")
        else:
            log.write(f"{content}: {finish_timestamp} incremental mdis path filter ended, used {duration}\n")
        


if __name__ == '__main__':
    main()