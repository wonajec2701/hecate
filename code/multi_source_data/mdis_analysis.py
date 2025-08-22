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
from textwrap import indent
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

def get_as_and_other_competitors(routes,as_invalid_from_roa_set,as_exact_prefix_competitor_set,as_parent_prefix_competitor_set,as_sub_prefix_competitor_set,other_invalid_from_roa_set,other_exact_prefix_competitor_set,other_parent_prefix_competitor_set,other_sub_prefix_competitor_set,roa_info,valid_as,valid_as_from_both,roa_invalid_dict,roa_list):    
    unmatched_length_roa=[]
    unmatched_as_roa=[]
    unmatched_both=[]
    invalid_asn=routes['route']['origin_asn'].replace('AS','')
    invalid_prefix=routes['route']['prefix']
    roa_unmatched_dict=[]
    for unmatched_roa in routes['validity']['VRPs']['unmatched_length']:   
        roa_unmatched_dict.append(unmatched_roa)
        unmatched_length_roa.append(unmatched_roa)
    
    for unmatched_roa in routes['validity']['VRPs']['both_unmatched']:
        roa_unmatched_dict.append(unmatched_roa)
        unmatched_both.append(unmatched_roa)
        roa_asn=unmatched_roa['asn'].replace("AS","")
        roa_prefix=unmatched_roa['prefix']
        roa_maxlength=unmatched_roa['max_length']
        asn_match =roa_asn.replace("AS", "")
        roa_info[asn_match]=f"{roa_prefix} {roa_maxlength}"
        valid_as_from_both.add(asn_match)
        valid_as.add(asn_match)
    
    for unmatched_roa in routes['validity']['VRPs']['unmatched_as']:
        roa_unmatched_dict.append(unmatched_roa)
        unmatched_as_roa.append(unmatched_roa)
        roa_asn=unmatched_roa['asn'].replace("AS","")
        roa_prefix=unmatched_roa['prefix']
        roa_maxlength=unmatched_roa['max_length']
        asn_match =roa_asn.replace("AS", "")
        roa_info[asn_match]=f"{roa_prefix} {roa_maxlength}"
        valid_as.add(asn_match)
    for unmatched_roa in roa_unmatched_dict:
        roa_asn=unmatched_roa['asn'].replace("AS","")
        roa_prefix=unmatched_roa['prefix']
        roa_maxlength=unmatched_roa['max_length']
        roa_list.append(f"{roa_asn} {roa_prefix} {roa_maxlength}")
        for roa_matched_invalid_route in roa_invalid_dict[roa_asn,roa_prefix,roa_maxlength]:
            #roa_match =re.match(r'(.*) (.*/\d{1,3})',roa_matched_invalid_route)
            roa_match_asn=roa_matched_invalid_route.split()[0]
            roa_match_prefix=roa_matched_invalid_route.split()[1]
            compared_flag=ip_compared(roa_match_prefix,invalid_prefix)
            if roa_match_asn==invalid_asn:
                if roa_match_prefix==invalid_prefix:
                    continue
                elif compared_flag==1:
                    as_parent_prefix_competitor_set.add(f"{roa_matched_invalid_route}")
                    as_invalid_from_roa_set.add(f"{roa_matched_invalid_route}|{roa_asn,roa_prefix,roa_maxlength}")
                elif compared_flag==2:
                    as_sub_prefix_competitor_set.add(f"{roa_matched_invalid_route}")
                    as_invalid_from_roa_set.add(f"{roa_matched_invalid_route}|{roa_asn,roa_prefix,roa_maxlength}")
            elif roa_match_asn!=invalid_asn:
                if roa_match_prefix==invalid_prefix:
                    other_exact_prefix_competitor_set.add(f"{roa_matched_invalid_route}")
                    other_invalid_from_roa_set.add(f"{roa_matched_invalid_route}|{roa_asn,roa_prefix,roa_maxlength}")
                elif compared_flag==1:
                    other_parent_prefix_competitor_set.add(f"{roa_matched_invalid_route}")
                    other_invalid_from_roa_set.add(f"{roa_matched_invalid_route}|{roa_asn,roa_prefix,roa_maxlength}")
                elif compared_flag==2:
                    other_sub_prefix_competitor_set.add(f"{roa_matched_invalid_route}")
                    #other_invalid_from_roa_set.add(f"{roa_matched_invalid_route}|{roa_asn,roa_prefix,roa_maxlength}")
    return unmatched_length_roa,unmatched_as_roa,unmatched_both

def ip_compared(ip1,ip2):
    if "." in ip1 and "." in ip2:
        pfx1=ip1.split("/")[0]
        length1=int(ip1.split("/")[1])
        pfxint1=int(ipaddress.IPv4Address(pfx1))
        pfxbinstr1=bin(pfxint1)[2:]
        pfxbinstr1='0'*(32-len(pfxbinstr1))+pfxbinstr1
        #print(f"{pfxbinstr1[:length1]}")

        pfx2=ip2.split("/")[0]
        length2=int(ip2.split("/")[1])
        pfxint2=int(ipaddress.IPv4Address(pfx2))
        pfxbinstr2=bin(pfxint2)[2:]
        pfxbinstr2='0'*(32-len(pfxbinstr2))+pfxbinstr2
        #print(f"{pfxbinstr2[:length2]}")

        net1=pfxbinstr1[:length1]
        net2=pfxbinstr2[:length2]

        if net1.startswith(net2):
            return 2#21
        elif net2.startswith(net1):
            return 1#12
    elif ":" in ip1 and ":" in ip2:
        pfx1=ip1.split("/")[0]
        length1=int(ip1.split("/")[1])
        pfxint1=int(ipaddress.IPv6Address(pfx1))
        pfxbinstr1=bin(pfxint1)[2:]
        pfxbinstr1='0'*(128-len(pfxbinstr1))+pfxbinstr1
        #print(f"{pfxbinstr1[:length1]}")

        pfx2=ip2.split("/")[0]
        length2=int(ip2.split("/")[1])
        pfxint2=int(ipaddress.IPv6Address(pfx2))
        pfxbinstr2=bin(pfxint2)[2:]
        pfxbinstr2='0'*(128-len(pfxbinstr2))+pfxbinstr2
        #print(f"{pfxbinstr2[:length2]}")

        net1=pfxbinstr1[:length1]
        net2=pfxbinstr2[:length2]

        if net1.startswith(net2):
            return 2#21
        elif net2.startswith(net1):
            return 1#12
    else:
        return 0

def get_as_org(as_org_list,asn):
    if not isinstance(asn,int):

        asn=int(asn)
    if asn>=411500:
        as_org_name='private'
        return as_org_name
    if as_org_list[asn]==0:
        as_org_name='unknown'
        return as_org_name
    else:
        as_org_name=as_org_list[asn]
        return as_org_name

def same_as_org(as_org_list,asn1,asn2):
    if not isinstance(asn1,int):
        asn1=int(asn1)
    if not isinstance(asn2,int):
        asn2=int(asn2)
    if asn1>=411500 or asn2>=411500:
        return False
    elif as_org_list[asn1]==0 or as_org_list[asn2]==0:
        return False
    elif as_org_list[asn1]==as_org_list[asn2]:
        return True
    else:
        return False 


def get_path_unmatched_as(total_as_prefix_dict,asn,prefix,invalid_as_path_dict,timestamp,valid_as,as_org_list,valid_asn_prefix_dict,total_as_path_json_file,other_invalid_from_roa_set,other_exact_prefix_competitor_set,other_parent_prefix_competitor_set,other_sub_prefix_competitor_set,as_relationship_dict,roa_info,recovery_roa_output):


    if len(other_exact_prefix_competitor_set)+len(other_parent_prefix_competitor_set)+len(other_sub_prefix_competitor_set)>0:
        other_competitor_flag=1
    else:
        other_competitor_flag=0
    is_allocation_flag=0
    competitor_flag='000'
    
    as_path=[]
    #as_relationship,same_org
    for roa_as in valid_as:
        if roa_as == '133588':
            print("here", roa_as, asn)
        if asn in as_relationship_dict and roa_as in as_relationship_dict.get(asn , []):
            continue_flag=0
            record_as=roa_as
            break
        elif roa_as in as_relationship_dict and asn in as_relationship_dict.get(roa_as , []):
            continue_flag=0
            record_as=roa_as
            break
        elif asn in as_relationship_dict["ixp"]:
            continue_flag=0
            record_as=roa_as
            break
        #same org
        elif same_as_org(as_org_list,roa_as,asn):
            continue_flag=2
            record_as=roa_as
            break
        else:
            continue_flag=1
    if continue_flag==0:
        as_path="sure"
        is_allocation_flag=4#as_relationship
        recovery_roa_output.write(f"{asn} {prefix} {record_as} as_relationship"+"\n")
        return as_path,is_allocation_flag,competitor_flag
    elif continue_flag==2:
        as_path="sure"
        is_allocation_flag=5#same_org
        recovery_roa_output.write(f"{asn} {prefix} {record_as} same_org"+"\n")
        return as_path,is_allocation_flag,competitor_flag
    #roa_as in path
    as_path=invalid_as_path_dict[(str(asn),prefix)]
    for as_path_to_check in as_path:
        numbers=as_path_to_check
        for item in valid_as:
            if str(item) in numbers:#roa as in path
                as_path="sure"
                is_allocation_flag=1#as_relationship
                recovery_roa_output.write(f"{asn} {prefix} {item} path={as_path_to_check} roa_as in path"+"\n")
                return as_path,is_allocation_flag,competitor_flag
    #competitor:single_host
    roa_competitor_as=set()
    parent_competitor_set=set()
    parent_of_roa_competitor_set=set()
    competitor_set=set()
    valid_parent_competitor_flag=0
    valid_roa_competitor_flag=0
    for item in valid_as:
        if item not in valid_asn_prefix_dict:
            continue
        else:
            valid_prefix_set=set(valid_asn_prefix_dict[item])
        if item in total_as_prefix_dict:
            route_prefixes=total_as_prefix_dict[item]
        else:
            continue
        for route_prefix in route_prefixes:
            compared_flag=ip_compared(prefix,route_prefix)
            if prefix==route_prefix:
                roa_competitor_as.add(item)
                if route_prefix in valid_prefix_set:
                    valid_roa_competitor_flag=1
                    competitor_set.add(f"valid:{item} {route_prefix}")
                else:
                    valid_roa_competitor_flag=0
                    competitor_set.add(f"{item} {route_prefix}")
            elif compared_flag==1:
                parent_of_roa_competitor_set.add(f"{item} {route_prefix}")
                competitor_set.add(f"{item} {route_prefix}")
            elif compared_flag==2:
                parent_competitor_set.add(f"{item} {route_prefix}")
                valid_prefix_set=set(valid_asn_prefix_dict[item])
                if route_prefix in valid_prefix_set:
                    valid_parent_competitor_flag=1
                    competitor_set.add(f"valid:{item} {route_prefix}")
                else:
                    valid_parent_competitor_flag=0
                    competitor_set.add(f"{item} {route_prefix}")
    if valid_roa_competitor_flag and other_competitor_flag and valid_parent_competitor_flag:
        competitor_flag='111'
    elif valid_roa_competitor_flag and other_competitor_flag and not valid_parent_competitor_flag:
        competitor_flag='110'
    elif valid_roa_competitor_flag and not other_competitor_flag and not valid_parent_competitor_flag:
        competitor_flag='100'
    elif valid_roa_competitor_flag and not other_competitor_flag and valid_parent_competitor_flag:
        competitor_flag='101'
    elif not valid_roa_competitor_flag and other_competitor_flag and valid_parent_competitor_flag:
        competitor_flag='011'
    elif not valid_roa_competitor_flag and not other_competitor_flag and valid_parent_competitor_flag:
        competitor_flag='001'
    elif not valid_roa_competitor_flag and other_competitor_flag and not valid_parent_competitor_flag:
        competitor_flag='010'
    elif not valid_roa_competitor_flag and not other_competitor_flag and not valid_parent_competitor_flag:
        competitor_flag='000'
        recovery_roa_output.write(f"{asn} {prefix} non-competitor"+"\n")
    return as_path,is_allocation_flag,competitor_flag
    
def get_valid_path_for_unmatched_length(invalid_asn,invalid_prefix,valid_asn_prefix_dict,invalid_as_path_dict,valid_as_path_dict):
    count_same=0
    count_different=0
    count_parent_same=0
    count_parent_different=0
    valid_path_set=set()
    valid_parent_path_set=set()
    suspicious_path_set=set()
    valid_parent_prefix_set=set()
    invalid_pathes_set=set()
    suspicious_path_set_parent=set()
    #print(invalid_asn)
    invalid_asn=invalid_asn.replace('AS', "")
    if invalid_asn not in valid_asn_prefix_dict:
        count_same=-1
        suspicious_path_set=invalid_pathes_set-valid_path_set
        return valid_path_set,suspicious_path_set,count_same,count_different,valid_parent_prefix_set,invalid_pathes_set
    valid_asn_prefix_set=set(valid_asn_prefix_dict[invalid_asn])

    
    for item in valid_asn_prefix_set:
        try:
            valid_pathes_list=set(valid_as_path_dict[(str(invalid_asn),item)])
        except KeyError:
            with open(f"{current_directory}/bgp_route/run-log/runlog",'a') as log:
                log.write(f"get_valid_path_for_unmatched_length:{(str(invalid_asn),item)} there is an keyerror"+"\n")     
            continue
        #invalid asvalid parent prefixpathvalid_path_set
        if ip_compared(item,invalid_prefix)==1:#iteminvalid prefix
            #print("valid_parent_prefix_set get")
            valid_path_set=valid_path_set.union(valid_pathes_list)
    if (str(invalid_asn),invalid_prefix) not in invalid_as_path_dict:#invalid asn prefixpath
        with open(f"{current_directory}/bgp_route/run-log/runlog",'a') as log:
            log.write(f"get_valid_path_for_unmatched_length2:{(str(invalid_asn),invalid_prefix)} there is an keyerror"+"\n")
        if (str(invalid_asn),invalid_prefix.replace(":0:","::",1)) in invalid_as_path_dict:
            invalid_pathes_list=set(invalid_as_path_dict[str(invalid_asn),invalid_prefix.replace(":0:","::",1)])
        elif (str(invalid_asn),invalid_prefix.replace(":0/","::/")) in invalid_as_path_dict:
            invalid_pathes_list=set(invalid_as_path_dict[str(invalid_asn),invalid_prefix.replace(":0/","::/")])
        else:
            print(str(invalid_asn))
            print(invalid_prefix)
            sys.exit(0)    
    else:
        invalid_pathes_list=set(invalid_as_path_dict[(str(invalid_asn),invalid_prefix)])

    invalid_pathes_set=set(invalid_pathes_list)
    suspicious_path_set=invalid_pathes_set-valid_path_set
    count_different=len(suspicious_path_set)
    same_path_set=invalid_pathes_set & valid_path_set
    count_same=len(same_path_set)  
    return valid_path_set,suspicious_path_set,count_same,count_different,valid_parent_prefix_set,invalid_pathes_set
    
def get_path_unmatched_length(roa_prefix,roa_maxlength,asn,prefix,invalid_as_path_dict,timestamp,as_org_list,valid_asn_prefix_dict,other_invalid_from_roa_set,other_exact_prefix_competitor_set,other_parent_prefix_competitor_set,other_sub_prefix_competitor_set,as_invalid_from_roa_set,as_parent_prefix_competitor_set,as_sub_prefix_competitor_set,count_total_same,count_partial_same,count_short_same,count_no_valid_vp_same,count_differnt,count_no_valid_prefix,as_relationship_dict,valid_as_path_dict,recovery_roa_output):
    


    valid_path_set,suspicious_path_set,count_same,count_different,valid_parent_prefix_set,invalid_pathes_set=get_valid_path_for_unmatched_length(asn,prefix,valid_asn_prefix_dict,invalid_as_path_dict,valid_as_path_dict)
    
    
    if count_different==0 and count_same>0:
        count_total_same[0]+=1
        recovery_roa_output.write(f"{asn} {prefix} same path"+"\n")
    elif count_different>0 and count_same>0:
        count_partial_same[0]+=1
        recovery_roa_output.write(f"{asn} {prefix} same path"+"\n")
    elif count_same==0 and count_different>0:
        VP_set=set()
        vp_path_dict={}

        #valid_prefix----------------------------
        count_vp_have_valid_path=0
        different_pathes_set=invalid_pathes_set-valid_path_set
        for different_path in different_pathes_set:
            numbers=different_path
            if numbers[0]==numbers[-1]:
                continue
            VP_set.add(numbers[0])#different_pathes_setVP
            if numbers[0] not in vp_path_dict:
                vp_path_dict[numbers[0]]={different_path}
            else:
                vp_path_dict[numbers[0]].add(different_path)
        same_VP_valid_set=set()
        traffic_eng_flag=0
        traffic_eng_count=0
        valid_vp_path_dict={}
        for valid_path in valid_path_set:
            numbers=valid_path
            if numbers[0]==numbers[-1]:
                continue
            if numbers[0] not in valid_vp_path_dict:
                valid_vp_path_dict[numbers[0]]={valid_path}
            else:
                valid_vp_path_dict[numbers[0]].add(valid_path)
        for vp in vp_path_dict:
            if vp in valid_vp_path_dict:
                for valid_path in valid_vp_path_dict[vp]:
                    valid_path_numbers=set(valid_path)
                    count_vp_have_valid_path+=1#vpvalid parent prefix path
                    same_VP_valid_set.add(valid_path)
                    remove_count=0
                    for different_path in vp_path_dict[vp]:
                        different_path_numbers=set(different_path)
                        diff=different_path_numbers-valid_path_numbers
                        if len(diff)==0:#
                            count_vp_have_valid_path-=1
                            traffic_eng_count+=1
                            traffic_eng_flag=1
                            try:
                                suspicious_path_set.discard(different_path)
                                remove_count+=1
                            except KeyError:
                                print(different_path)
                                print('suspicious_path_set=',suspicious_path_set)
                                sys.exit(0)
                    if remove_count==len(vp_path_dict[vp]):
                        break
        if count_vp_have_valid_path==0:#（VP-ASpathvalid path），valid VP path，different pathesvalid path
            if traffic_eng_flag:#VP，valid path 
                count_short_same[0]+=1
                recovery_roa_output.write(f"{asn} {prefix} short same path"+"\n")
            else:#count_vp_have_valid_path==0，VP valid path
                count_no_valid_vp_same[0]+=1
        elif count_vp_have_valid_path>0:#VPvalid pathinvalid prefix path
            if traffic_eng_flag:#，valid path,count_same>0
                count_short_same[0]+=1
                recovery_roa_output.write(f"{asn} {prefix} short same path"+"\n")
            else:
                count_differnt[0]+=1

    elif count_same==-1:
        count_no_valid_prefix[0]+=1
        
    
    if len(valid_parent_prefix_set):
        valid_parent_prefix_flag=1
    else:
        valid_parent_prefix_flag=0
    if len(other_invalid_from_roa_set):
        other_competitor_flag=1
    else:
        other_competitor_flag=0
    if valid_parent_prefix_flag and other_competitor_flag:
        competitor_flag='11'
    elif not valid_parent_prefix_flag and other_competitor_flag:
        competitor_flag='01' 
    elif not valid_parent_prefix_flag and not other_competitor_flag:
        competitor_flag='00'
    elif valid_parent_prefix_flag and not other_competitor_flag:
        competitor_flag='10'

    return competitor_flag

def get_valid_as_path(valid_asn_prefix_dict,invalid_as_path_dict,timestamp,invalid_as_file):
    valid_as_path_dict={}
    num = 0
    with open(invalid_as_file,'r') as invalid_as:
        invalid_as_list=invalid_as.readline()
        progress_bar = tqdm(valid_asn_prefix_dict.items(), desc=f'get_valid_as_path', unit='line', unit_scale=True, leave=True,file=sys.stdout)
        for key,value in valid_asn_prefix_dict.items():
            progress_bar.update(1)
            prefix_set=set(value)
            asn=str(key)
            if asn not in invalid_as_list:
                continue
            for valid_prefix in prefix_set:
                #progress_bar.update(1)
                try:
                    valid_pathes_set_to_check=set(invalid_as_path_dict[str(asn),valid_prefix])
                    valid_as_path_dict[str(asn),valid_prefix]=list(valid_pathes_set_to_check)   
                except:
                    num += 1
                    print(num, str(asn),valid_prefix)
    return  valid_as_path_dict

def match_routes_analysis(invalid_routes,timestamp,invalid_as_path_file,as_org_list,total_as_path_json_file,roa_invalid_dict,as_relationship_dict,invalid_as_file):
    if increment == 0:
        valid_asn_prefix_file=f"{current_directory}/bgp_route/checklog/valid/mdis_valid-asn_prefix-output-{timestamp}_{content}.txt"
        recovery_roa_output_file=f"{current_directory}/bgp_route/result/mdis_result-tag-{timestamp}_{content}"
    elif increment == 2:
        valid_asn_prefix_file=f"{current_directory}/bgp_route/checklog/valid/add-mdis_valid-asn_prefix-output-{timestamp}_{content}.txt"
        recovery_roa_output_file=f"{current_directory}/bgp_route/result/add-mdis_result-tag-{timestamp}_{content}"
    if not os.path.exists(os.path.dirname(recovery_roa_output_file)):
        os.makedirs(os.path.dirname(recovery_roa_output_file))
    
    #valid_asn_prefix_dict
    valid_asn_prefix_dict={}
    lines=[]
    with open(valid_asn_prefix_file,'r') as valid_asn_prefix:
        lines=valid_asn_prefix.readlines()
    progress_bar = tqdm(lines, desc=f'valid-asn-prefix-dict', unit='line', unit_scale=True, leave=True,file=sys.stdout)
    for item in lines:
        progress_bar.update(1)
        parts = item.split(' ')
        key1 = parts[0].replace('AS', "")
        if (key1) not in valid_asn_prefix_dict:
            valid_asn_prefix_dict[key1] = []
        values=valid_asn_prefix_dict[key1]
        values.append(parts[1])
        valid_asn_prefix_dict[key1]=values
    progress_bar.close()
    del lines
    gc.collect()

    as_counts=0
    allocation_count=0
    total_allocation_count=0
    invalid_as_path_dict={}
    lines=[]
    with open(invalid_as_path_file,'r') as invalid_as_path:
        lines=invalid_as_path.readlines()
    valid_as_path_dict={}
    
    progress_bar = tqdm(lines, desc=f'invalid-path-dict', unit='line', unit_scale=True, leave=True,file=sys.stdout)  
    for item in lines:
        try:
            progress_bar.update(1)
            parts = item.split()
            key1 = parts[0]
            key2 = parts[1]
            path = parts[2:]#pathlistset
            if (key1,key2) not in invalid_as_path_dict:
                invalid_as_path_dict[key1,key2]={tuple(path)}
            else:
                invalid_as_path_dict[key1,key2].add(tuple(path))
        except KeyError:
            print(item)
            sys.exit(0)
    progress_bar.close()
    del lines
    gc.collect()
    
    
    
    valid_as_path_dict=get_valid_as_path(valid_asn_prefix_dict,invalid_as_path_dict,timestamp,invalid_as_file)
    
    with open(recovery_roa_output_file,'a') as recovery_roa_output:
        
        count_valid_roa_competitor=0
        count_valid_parent_competitor=0
        count_other_competitor=0
        
        count_unmatched_length=0
        
        count_000=0
        count_001=0
        count_010=0
        count_011=0
        count_100=0
        count_101=0
        count_110=0
        count_111=0
        
        count_length_other_competitor=0
        count_length_valid_parent=0
        count_length_invalid_p_c_competitor=0
        count_00=0
        count_01=0
        count_10=0
        count_11=0

        count_total_same=[0]
        count_partial_same=[0]
        count_short_same=[0]
        count_no_valid_vp_same=[0]
        count_differnt=[0]
        count_no_valid_prefix=[0]
        
        total_as_prefix_dict={}
        with open(total_as_path_json_file,'rb') as total_as_path_json:
            total_as_prefix_dict=pickle.load(total_as_path_json)
        del total_as_path_json
        gc.collect()    
        
        progress_bar = tqdm(invalid_routes, desc=f'invalid-info', unit='line', unit_scale=True, leave=True,file=sys.stdout)
        for routes in invalid_routes:
            progress_bar.update(1)
            the_invalid_asn=routes['route']['origin_asn'].replace("AS","")
            the_invalid_prefix=routes['route']['prefix']
            if routes["validity"]["reason"]=='length':
                count_unmatched_length+=1
                valid_as=set()
                valid_as_from_both=set()
                roa_info={}
                roa_list=[]
                as_invalid_from_roa_set=set()
                as_exact_prefix_competitor_set=set()
                as_parent_prefix_competitor_set=set()
                as_sub_prefix_competitor_set=set()
                
                other_invalid_from_roa_set=set()
                other_exact_prefix_competitor_set=set()
                other_parent_prefix_competitor_set=set()
                other_sub_prefix_competitor_set=set()

                
                roa_prefix=[]
                roa_maxlength=[]
                
                #as and other competitor
                get_as_and_other_competitors(routes,as_invalid_from_roa_set,as_exact_prefix_competitor_set,as_parent_prefix_competitor_set,as_sub_prefix_competitor_set,other_invalid_from_roa_set,other_exact_prefix_competitor_set,other_parent_prefix_competitor_set,other_sub_prefix_competitor_set,roa_info,valid_as,valid_as_from_both,roa_invalid_dict,roa_list)      

                competitor_flag=get_path_unmatched_length(roa_prefix,roa_maxlength,the_invalid_asn,the_invalid_prefix,invalid_as_path_dict,timestamp,as_org_list,valid_asn_prefix_dict,other_invalid_from_roa_set,other_exact_prefix_competitor_set,other_parent_prefix_competitor_set,other_sub_prefix_competitor_set,as_invalid_from_roa_set,as_parent_prefix_competitor_set,as_sub_prefix_competitor_set,count_total_same,count_partial_same,count_short_same,count_no_valid_vp_same,count_differnt,count_no_valid_prefix,as_relationship_dict,valid_as_path_dict,recovery_roa_output)
                #print(competitor_flag)
                if competitor_flag=='11':
                    count_11+=1
                    count_length_valid_parent+=1
                    count_length_other_competitor+=1
                elif competitor_flag=='10':
                    count_10+=1
                    recovery_roa_output.write(f"{the_invalid_asn} {the_invalid_prefix} non-other-competitor"+"\n")
                    count_length_valid_parent+=1
                    count_length_other_competitor+=0
                elif competitor_flag=='01':
                    count_01+=1
                    count_length_valid_parent+=0
                    count_length_other_competitor+=1   
                elif competitor_flag=='00':
                    recovery_roa_output.write(f"{the_invalid_asn} {the_invalid_prefix} non-competitor"+"\n")
                    count_00+=1
                    count_length_valid_parent+=0
                    count_length_other_competitor+=0

                if competitor_flag=='00' and len(as_invalid_from_roa_set)==0:
                    count_length_invalid_p_c_competitor+=1

            if routes["validity"]["reason"]=='as':
                valid_as=set()
                valid_as_from_both=set()
                roa_info={}
                roa_list=[]
                as_invalid_from_roa_set=set()
                as_exact_prefix_competitor_set=set()
                as_parent_prefix_competitor_set=set()
                as_sub_prefix_competitor_set=set()
                other_invalid_from_roa_set=set()
                other_exact_prefix_competitor_set=set()
                other_parent_prefix_competitor_set=set()
                other_sub_prefix_competitor_set=set()
                as_counts+=1

                roa_info={}
                
                get_as_and_other_competitors(routes,as_invalid_from_roa_set,as_exact_prefix_competitor_set,as_parent_prefix_competitor_set,as_sub_prefix_competitor_set,other_invalid_from_roa_set,other_exact_prefix_competitor_set,other_parent_prefix_competitor_set,other_sub_prefix_competitor_set,roa_info,valid_as,valid_as_from_both,roa_invalid_dict,roa_list)
                        
                valid_as=set(valid_as)
                
                the_invalid_asn=routes['route']['origin_asn'].replace('AS', "")
                the_invalid_prefix=routes['route']['prefix']
                    
                the_invalid_as_pathes,is_allocation_flag,competitor_flag=get_path_unmatched_as(total_as_prefix_dict,the_invalid_asn,the_invalid_prefix,invalid_as_path_dict,timestamp,valid_as,as_org_list,valid_asn_prefix_dict,total_as_path_json_file,other_invalid_from_roa_set,other_exact_prefix_competitor_set,other_parent_prefix_competitor_set,other_sub_prefix_competitor_set,as_relationship_dict,roa_info,recovery_roa_output)
                if is_allocation_flag==1:
                    allocation_count+=1
                if is_allocation_flag==4:#as_relationship
                    allocation_count+=1
                    total_allocation_count+=1
                if is_allocation_flag==5:#same_org
                    allocation_count+=1
                    total_allocation_count+=1
                if competitor_flag=='111':
                    count_111+=1
                    count_other_competitor+=1
                    count_valid_roa_competitor+=1
                    count_valid_parent_competitor+=1
                elif competitor_flag=='110':
                    count_110+=1
                    count_other_competitor+=1
                    count_valid_roa_competitor+=1
                    count_valid_parent_competitor+=0
                elif competitor_flag=='101':
                    count_101+=1
                    count_other_competitor+=1
                    count_valid_roa_competitor+=0
                    count_valid_parent_competitor+=1    
                elif competitor_flag=='100':
                    count_100+=1
                    count_other_competitor+=1
                    count_valid_roa_competitor+=0
                    count_valid_parent_competitor+=0
                elif competitor_flag=='000':
                    count_000+=1
                    count_other_competitor+=0
                    count_valid_roa_competitor+=0
                    count_valid_parent_competitor+=0
                elif competitor_flag=='001':
                    count_001+=1
                    count_other_competitor+=0
                    count_valid_roa_competitor+=0
                    count_valid_parent_competitor+=1
                elif competitor_flag=='011':
                    count_011+=1
                    count_other_competitor+=0
                    count_valid_roa_competitor+=1
                    count_valid_parent_competitor+=1
                elif competitor_flag=='010':
                    count_010+=1
                    count_other_competitor+=0
                    count_valid_roa_competitor+=1
                    count_valid_parent_competitor+=0
    
def main():
    start_time = datetime.now()
    start_timetamp = start_time.strftime("%Y%m%d %H:%M:%S")
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        if increment == 0:
            log.write(f"{content}: {start_timetamp} mdis analysis started\n")
        else:
            log.write(f"{content}: {start_timetamp} incremental mdis analysis started\n")

    print("....")
    now = datetime.now()-timedelta(hours=60)
    
    timestamp=now.strftime("%Y%m%d")
    year = current_directory.split('-')[0]
    month = current_directory.split('-')[1]
    day = current_directory.split('-')[2]
    timestamp = year+month+day
    print(f"{timestamp}")


    analysis_time=time.time()
    #=================
    if increment == 0:
        invalid_file=f"{current_directory}/bgp_route/checklog/invalid/mdis_invalid-output-{timestamp}_{content}.json"
        total_as_path_json_file = f"{current_directory}/bgp_route/path/mdis_total-path-json-{timestamp}_{content}"
        invalid_as_file=f"{current_directory}/bgp_route/analysis/invalid/mdis_invalid_as-{timestamp}_{content}"
        invalid_as_path_file=f"{current_directory}/bgp_route/analysis/invalid/mdis_invalid_as_path-{timestamp}_{content}"
    elif increment == 2:
        invalid_file=f"{current_directory}/bgp_route/checklog/invalid/add-mdis_invalid-output-{timestamp}_{content}.json"
        total_as_path_json_file = f"{current_directory}/bgp_route/path/add-mdis_total-path-json-{timestamp}_{content}"
        invalid_as_file=f"{current_directory}/bgp_route/analysis/invalid/add-mdis_invalid_as-{timestamp}_{content}"
        invalid_as_path_file=f"{current_directory}/bgp_route/analysis/invalid/add-mdis_invalid_as_path-{timestamp}_{content}"
    #-------------------------
    


    #=====
    if increment == 0:
        cmd= f"rm -rf {current_directory}/bgp_route/result/mdis_*{timestamp}_{content}"
        subprocess.check_output(cmd, shell=True, universal_newlines=True)
    elif increment == 2:
        cmd= f"rm -rf {current_directory}/bgp_route/result/add-mdis_*{timestamp}_{content}"
        subprocess.check_output(cmd, shell=True, universal_newlines=True)
    #============as_relationship_dict
    
    #as_relationship_input_file=f"{current_directory}/CAIDA/relationship/{relationshiptimestamp}01.as-rel2.txt"
    as_relationship_input_file=f"CAIDA/relationship/as-rel2.txt"
    as_relationship_dict={}
    with open(as_relationship_input_file,'r') as as_relationship:
        lines=as_relationship.readlines()
        progress_bar = tqdm(lines, desc=f'as_relationship_dict', unit='line', unit_scale=True, leave=True,file=sys.stdout)
        search_term='#'
        for line in lines:
            progress_bar.update(1)
            if line.startswith("# IXP ASes:"):
                as_numbers=line.replace("# IXP ASes:","").split(' ')
                as_relationship_dict["ixp"]=list(as_numbers)
                continue
            if line.startswith(search_term):
                continue
            as_numbers=line.split('|')
            #print(as_numbers[2])
            if as_numbers[2]=="-1":
                #print(as_numbers)
                provider_as=as_numbers[0]
                customer_as=as_numbers[1]
                if (provider_as) not in as_relationship_dict:
                    as_relationship_dict[provider_as]=[]
                values=as_relationship_dict[provider_as]
                values.append(customer_as)
                as_relationship_dict[provider_as]=values
            elif as_numbers[2]=="0":
                #print(as_numbers)
                peer1_as=as_numbers[0]
                peer2_as=as_numbers[1]
                if (peer1_as) not in as_relationship_dict:
                    as_relationship_dict[peer1_as]=[]
                values=as_relationship_dict[peer1_as]
                values.append(peer2_as)
                as_relationship_dict[peer1_as]=values
                if (peer2_as) not in as_relationship_dict:
                    as_relationship_dict[peer2_as]=[]
                values=as_relationship_dict[peer2_as]
                values.append(peer1_as)
                as_relationship_dict[peer2_as]=values      
    #return
    #============as_org_list
    asn_org=f'CAIDA/as_org/as-org2info.txt'
    as_org_list=[0]*411500
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
    #=================roa_invalid_dict，roa，
    invalid_routes={}
    roa_invalid_dict={}
    data_json={}
    with open(invalid_file,'r') as invalid_route_input:
        data_json=json.load(invalid_route_input)
        invalid_routes=data_json.get("validated_routes", [])
    progress_bar = tqdm(invalid_routes, desc=f'roa_invalid_dict', unit='line', unit_scale=True, leave=True,file=sys.stdout)
    for routes in invalid_routes:
        progress_bar.update(1)
        if routes["validity"]['VRPs']['unmatched_length']:
            for unmatched_roa in routes["validity"]['VRPs']['unmatched_length']:
                roa_asn=unmatched_roa['asn'].replace("AS","")
                roa_prefix=unmatched_roa['prefix']
                roa_max_length=unmatched_roa['max_length']
                if (roa_asn,roa_prefix,roa_max_length) in roa_invalid_dict:
                    roa_invalid_dict[roa_asn,roa_prefix,roa_max_length].add(routes['route']['origin_asn'].replace('AS','') +' '+ routes['route']['prefix'])
                else:
                    roa_invalid_dict[roa_asn,roa_prefix,roa_max_length]={routes['route']['origin_asn'].replace('AS','') +' '+ routes['route']['prefix']}
        if routes["validity"]['VRPs']['unmatched_as']:
            for unmatched_roa in routes["validity"]['VRPs']['unmatched_as']:
                roa_asn=unmatched_roa['asn'].replace("AS","")
                roa_prefix=unmatched_roa['prefix']
                roa_max_length=unmatched_roa['max_length']
                if (roa_asn,roa_prefix,roa_max_length) in roa_invalid_dict:
                    roa_invalid_dict[roa_asn,roa_prefix,roa_max_length].add(routes['route']['origin_asn'].replace('AS','') +' '+ routes['route']['prefix'])
                else:
                    roa_invalid_dict[roa_asn,roa_prefix,roa_max_length]={routes['route']['origin_asn'].replace('AS','') +' '+ routes['route']['prefix']}
        
        if routes["validity"]['VRPs']['both_unmatched']:
            for unmatched_roa in routes["validity"]['VRPs']['both_unmatched']:
                roa_asn=unmatched_roa['asn'].replace("AS","")
                roa_prefix=unmatched_roa['prefix']
                roa_max_length=unmatched_roa['max_length']
                if (roa_asn,roa_prefix,roa_max_length) in roa_invalid_dict:
                    roa_invalid_dict[roa_asn,roa_prefix,roa_max_length].add(routes['route']['origin_asn'].replace('AS','') +' '+ routes['route']['prefix'])
                else:
                    roa_invalid_dict[roa_asn,roa_prefix,roa_max_length]={routes['route']['origin_asn'].replace('AS','') +' '+ routes['route']['prefix']}
        
    #===============
    match_routes_analysis(invalid_routes,timestamp,invalid_as_path_file,as_org_list,total_as_path_json_file,roa_invalid_dict,as_relationship_dict,invalid_as_file)
    match_routes_analysis_time=time.time() 
    print("match_routes_analysis，："+time.strftime("%H:%M:%S", time.gmtime(match_routes_analysis_time-analysis_time)))
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_time = datetime.now()
        duration = finish_time - start_time
        log.write("match_routes_analysis，："+time.strftime("%H:%M:%S", time.gmtime(match_routes_analysis_time-analysis_time)) + "\n")
    
    if increment == 0:
        input=f"{current_directory}/bgp_route/result/mdis_result-tag-{timestamp}_{content}"
        output=f"{current_directory}/bgp_route/result/mdis_cro-{current_directory}_{content}"
    elif increment == 2:
        input=f"{current_directory}/bgp_route/result/add-mdis_result-tag-{timestamp}_{content}"
        output=f"{current_directory}/bgp_route/result/add-mdis_cro-{current_directory}_{content}"
    with open(input,'r') as inp,open(output,'w') as outp:
        lines=inp.readlines()
        recovery_set=set()
        for line in lines:
            if line.startswith("AS"):
                line=line.replace("AS","")
            nums=line.split()
            asn=nums[0]
            prefix=nums[1]
            reason=nums[2]
            if reason =="":
                continue
            maxlength=prefix.split("/")[1]
            recovery_set.add(f"{asn} {prefix} {maxlength}")
        for items in recovery_set:
            outp.write(f"{items}"+"\n")
        outp.write(f"{len(recovery_set)}")
    analysis_end_time=time.time()
    with open(f"{current_directory}/bgp_route/run-log/log-{timestamp}",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        log.write(f"{finish_timestamp} analysis，："+time.strftime("%H:%M:%S", time.gmtime(analysis_end_time-analysis_time))+"\n")
    print("analysis，："+time.strftime("%H:%M:%S", time.gmtime(analysis_end_time-analysis_time)))
    
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        duration = finish_time - start_time
        if increment == 0:
            log.write(f"{content}: {finish_timestamp} mdis analysis ended, used {duration}\n")
        else:
            log.write(f"{content}: {finish_timestamp} incremental mdis analysis ended, used {duration}\n")
       
if __name__ == '__main__':
    main()