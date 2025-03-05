#!/usr/bin/env python

import gc
import glob
import ipaddress
import json
import multiprocessing
import os
#import bgpdump
import random
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta
from typing import List
from tqdm import tqdm

from package import mio, pfxrov
from source_analysis import checkspeasn
#current_directory = os.getcwd()
current_directory = sys.argv[1]

def getspemap(spemap4, spemap6 ,spelist):
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
    


def process_file(file_name,processid,timestamp,collector,read_seq,collector_seq,counter_as_set,spemap4,spemap6, flag=0):

    # ，、、
    
    count=0
    filename_output_list = f"{current_directory}/bgp_route/list/list-output-{collector}-{timestamp}-{read_seq}-{processid}"
    as_set_file=f"{current_directory}/bgp_route/as-set/as-set-{timestamp}.txt"
    if not os.path.exists(os.path.dirname(filename_output_list)):
        os.makedirs(os.path.dirname(filename_output_list))
    filename_output_path = f"{current_directory}/bgp_route/path/path-output-{collector}-{timestamp}-{read_seq}-{processid}"
    if not os.path.exists(os.path.dirname(filename_output_path)):
        os.makedirs(os.path.dirname(filename_output_path))
    with open(filename_output_list, 'w') as output_file2 , open(as_set_file,'a') as as_set_record, open(filename_output_path,'w') as output_file3:
        #total_file_size = len(file_name)  #    
        progress_bar = tqdm(file_name, desc=f'Processing：{collector_seq}-{collector}-{read_seq}-{processid}', unit='line', unit_scale=True, leave=True,file=sys.stdout)
        list_to_check=[]
        path_to_check=[]
        for line in file_name:
            if not line:
                continue
            # 
            # 
            progress_bar.update(1)
            #time.sleep(1)
            #  split 
            #result = split(line)
            # 
            str=line.split('|')
            #print(f"{line}")
            if len(str) > 14 and flag == 1:
                str.pop(6)
            prefix = str[5]
            community= str[11]
            if  prefix.startswith("::ffff:"):
                items=prefix.replace("::ffff:",'').split("/")
                length=int(items[1])-96
                prefix=f"{items[0]}/{length}"
                print(prefix)
            if ":" not in prefix and checkspepfx(spemap4, pfxrov.getpfxbin(prefix.split("/")[0],int(prefix.split("/")[1])), int(prefix.split("/")[1]))==True:
                continue
            elif ":" in prefix and checkspepfx(spemap6, pfxrov.getpfxbin(prefix.split("/")[0],int(prefix.split("/")[1])), int(prefix.split("/")[1]))==True:
                continue
            as_path = str[6]
            ases=as_path.split(" ")
            flag_path_poison=0
            path_stack=[]
            for item in ases:
                if item not in path_stack:
                    path_stack.append(item)
                elif item in path_stack and item!=path_stack[-1]:
                    flag_path_poison=1
                    break
                elif item in path_stack and item==path_stack[-1]:
                    continue
            if flag_path_poison==1:
                path_filter_log=f"{current_directory}/bgp_route/checklog/path_filter/path_filter-{timestamp}"
                if not os.path.exists(os.path.dirname(path_filter_log)):
                    os.makedirs(os.path.dirname(path_filter_log))
                with open(f"{current_directory}/bgp_route/checklog/path_filter/path_filter-{timestamp}",'a') as log:
                    log.write(f"{ases} there is an flag_path_poison"+"\n")
                continue
            try:
                pattern = r'\{[^}]*\d+[^}]*\}'
                if re.search(pattern, as_path):
                    counter_as_set[0]+=1
                    as_set_record.write(as_path+"\n")
                    continue
            except IndexError:
                with open(f"{current_directory}/bgp_route/run-log/runlog",'a') as log:
                    log.write(f"{line} there is an error"+"\n")

            try:
                nums = re.findall(r'\d+', as_path.split()[-1])
            except IndexError:
                with open(f"{current_directory}/bgp_route/run-log/runlog",'a') as log:
                    log.write(f"{line} there is an error"+"\n")
            '''
            if len(nums)>1 :
                counter_as_set[0]+=1
                as_set_record.write(as_path+"\n")
                continue
            '''
            if len(nums)>0:
                asn = int(nums[0].replace("{","").replace("}",""))
            else :
                continue
            # 
            #  routes 
            #  routes 
            if checkspeasn(int(asn)) == True:
                continue
            as_prefix=f"{asn} {prefix}"
            as_prefix_path=f"{asn} {prefix} {as_path}"
            
            path_to_check.append(f"{as_prefix_path}")
            list_to_check.append(f"{as_prefix}")
            
        list_to_check=list(set(list_to_check))        
        count=len(list_to_check)
        for item in list_to_check:
            output_file2.write(f"{item}"+"\n")
        print(f"{collector}{processid}，{count},{counter_as_set[0]}asset"+'\n')
        
        path_to_check=list(set(path_to_check))
        count=len(path_to_check)
        for item in path_to_check:
            output_file3.write(f"{item}"+"\n")
        print(f"{collector}{processid}，{count}"+'\n')
    
def pch_process(ip_type,pch_collector_list,year,month,day,timestamp,counter_as_set,processid,spemap4,spemap6):
    current_dir = os.getcwd()
    count=0
    for type in ip_type:
        for collector in pch_collector_list:
            path_to_check=[]
            list_to_check=[]
            #print(f"pch:{collector}====================================")
            inputname=f'{current_directory}/bgp_route/download/pch/{collector}-ipv{type}_bgp_routes.{year}.{month}.{day}'
            #print(inputname)
            filename_output_list = f"{current_directory}/bgp_route/list/list-output-{collector}-ipv{type}-{timestamp}"
            filename_output_path = f"{current_directory}/bgp_route/path/path-output-{collector}-ipv{type}-{timestamp}"
            as_set_file=f"{current_directory}/bgp_route/as-set/as-set-{timestamp}.txt"

            if not os.path.exists(os.path.dirname(filename_output_list)):
                os.makedirs(os.path.dirname(filename_output_list))
            if not os.path.exists(os.path.dirname(filename_output_path)):
                os.makedirs(os.path.dirname(filename_output_path))
            if not os.path.exists(os.path.dirname(as_set_file)):
                os.makedirs(os.path.dirname(as_set_file))


            local_as="3856"
            if not os.path.exists(inputname) :
                print(f"{inputname}，collector")
                continue
            with open(inputname, 'r') as input_file,open(filename_output_list, 'w') as output_file2 , open(as_set_file,'a') as as_set_record, open(filename_output_path,'w') as output_file3:
                pre_prefix="1.0.0.0/24"
                lines=input_file.readlines()
                size=len(lines)
                del lines
                gc.collect()
                input_file.seek(0)
                line=input_file.readline()
                #print(inputname)
                progress_bar = tqdm(total=size, desc=f'pch-{processid}-{collector}-{type}', unit='line', unit_scale=True, leave=True,file=sys.stdout)
                end_flag=["i","e","?"]
                while line:
                    progress_bar.update(1)
                    if line.startswith('*') and "error" not in line:
                        str=line.replace("*i","").replace("h","").replace("*s","").replace("d ","").replace("*","").replace("=","").replace(">","").replace("*r","").replace("S","").replace("R","").split()
                        #print(f"{line}")
                        #print(line)
                        prefix_0_1=str
                        while (str[-1] not in end_flag):
                            next_line=input_file.readline()
                            line=line+next_line
                            str=line.replace("*i","").replace("h","").replace("s","").replace("d ","").replace("*","").replace("=","").replace(">","").replace("r","").replace("S","").replace("R","").split()
                            #print(line)
                            prefix_0_2=str
                        if str[1]!='0' and str[3]!='0':
                            pre_prefix=str[0]
                            prefix = str[0]
                            as_path = str[3:]
                        elif str[1]!='0' and str[3]=='0':
                            pre_prefix=str[0]
                            prefix = str[0]
                            as_path = str[4:]
                        elif str[-1]=="error!":
                            print(line)
                            break
                        else:
                            prefix = pre_prefix
                            as_path = str[3:]
                        #print(as_path)
                        
                        lengthmatch=re.match(r"(.*)/(\d+)", prefix)
                        if not lengthmatch:
                            #print(prefix)
                            lengthmatch=re.match(r"(\d+\.\d+\.\d+\.\d+)", prefix)
                            if not lengthmatch:
                                lengthmatch=re.match(r"(.*)", prefix)
                                if len(lengthmatch.group(1).split(':'))==1:
                                    actual_length='16'
                                elif len(lengthmatch.group(1).split(':'))==2:
                                    actual_length='32'
                                elif len(lengthmatch.group(1).split(':'))==3:
                                    actual_length='48'
                                elif len(lengthmatch.group(1).split(':'))==4:
                                    actual_length='64'
                                elif len(lengthmatch.group(1).split(':'))==5:
                                    actual_length='80'
                                elif len(lengthmatch.group(1).split(':'))==6:
                                    actual_length='96'
                                elif len(lengthmatch.group(1).split(':'))==7:
                                    actual_length='112'
                                elif len(lengthmatch.group(1).split(':'))==8:
                                    actual_length='128'
                                prefix=lengthmatch.group(1)+'/'+actual_length
                            else:
                                if lengthmatch.group(1).split('.')[1]=='0' and lengthmatch.group(1).split('.')[2]=='0' and lengthmatch.group(1).split('.')[3]=='0':
                                    actual_length='8'
                                elif lengthmatch.group(1).split('.')[2]=='0' and lengthmatch.group(1).split('.')[3]=='0':
                                    actual_length='16'
                                elif lengthmatch.group(1).split('.')[3]=='0':
                                    actual_length='24'
                            prefix=lengthmatch.group(1)+'/'+actual_length
                        try:
                            path_filter_log=f"{current_directory}/bgp_route/checklog/path_filter/path_filter-{timestamp}"
                            if not os.path.exists(os.path.dirname(path_filter_log)):
                                os.makedirs(os.path.dirname(path_filter_log))
                            if ":" not in prefix and checkspepfx(spemap4, pfxrov.getpfxbin(prefix.split("/")[0],int(prefix.split("/")[1])), int(prefix.split("/")[1]))==True:
                                line=input_file.readline() 
                                with open(path_filter_log,'a') as log:
                                    log.write(f"{prefix} {collector} there is an Ipv4 erorr"+"\n")
                                continue
                            elif ":" in prefix and checkspepfx(spemap6, pfxrov.getpfxbin(prefix.split("/")[0],int(prefix.split("/")[1])), int(prefix.split("/")[1]))==True:
                                line=input_file.readline() 
                                with open(path_filter_log,'a') as log:
                                    log.write(f"{prefix} {collector} there is an Ipv6 erorr"+"\n")
                                continue
                        except IndexError:
                            print(prefix)
                            print("warining!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                            sys.exit(0)
                        #print(prefix)
                        if len(as_path)==1 and as_path[0]=="i":
                            asn=local_as
                        else:
                            try:
                                asn=as_path[-2]
                                
                            except IndexError:
                                print(collector+type)
                                print(line)
                                print(prefix)
                                print(as_path)
                                print("warning!=========================================================================================")
                                sys.exit(0) 
                        
                        if len(asn.replace("{","").replace("}","").split(","))>1:
                            as_set_record.write(f"{line} in {inputname}"+"\n")
                            line=input_file.readline() 
                            continue
                        else:
                            asn=asn.replace("{","").replace("}","")
                        # flag_path_poison  
                        
                        flag_path_poison=0
                        path_stack=[]
                        pre_hop="xxxx"
                        if len(as_path)>1:
                            for item in as_path:
                                if item==pre_hop:
                                    
                                    continue
                                else:
                                    pre_hop=item
                                if item not in path_stack:
                                    path_stack.append(item)
                                    
                                elif item in path_stack:
                                    flag_path_poison=1
                                    break
                            if flag_path_poison==1:
                                path_filter_log=f"{current_directory}/bgp_route/checklog/path_filter/path_filter-{timestamp}"
                                if not os.path.exists(os.path.dirname(path_filter_log)):
                                    os.makedirs(os.path.dirname(path_filter_log))
                                with open(path_filter_log,'a') as log:
                                    log.write(f"{as_path} there is an flag_path_poison"+"\n")
                                line=input_file.readline()
                                continue
                        
                        if len(as_path)>1:
                            as_path=as_path[:-1]#i
                            as_path_str=as_path[0]
                            if len(as_path)>1:
                                for item in as_path[1:]:
                                    as_path_str=as_path_str+' '+item
                            for item in as_path:
                                if item not in as_path_str:
                                    print(as_path_str)
                                    print(as_path)
                                    sys.exit(0)
                        elif len(as_path)==1 and as_path[0]=="i":
                            as_path_str=local_as
                        if checkspeasn(int(asn)) == True:
                            continue
                        as_prefix=f"{asn} {prefix}"
                        as_prefix_path=f"{asn} {prefix} {as_path_str}"
                        path_to_check.append(f"{as_prefix_path}")
                        list_to_check.append(f"{as_prefix}")
                        line=input_file.readline() 
                    else:
                        if line.startswith("Default"):
                            str=line.split()
                            local_as=str[-1]
                        line=input_file.readline()
        
                list_to_check=list(set(list_to_check))        
                #count+=len(list_to_check)
                for item in list_to_check:
                    output_file2.write(f"{item}"+"\n")
                #print(f"{collector}-ipv{type}，{count},{counter_as_set[0]}asset"+'\n')
                
                path_to_check=list(set(path_to_check))
                count+=len(path_to_check)
                for item in path_to_check:
                    output_file3.write(f"{item}"+"\n")
                #print(f"{collector}-ipv{type}，{count}"+'\n')
    print(f"{processid}，{count}")
    #print(f"{processid}")






def read_file_by_lines(file, num_lines):
        lines = []
        for i, line in enumerate(file):
            lines.append(line)
            if (i + 1) % num_lines == 0:
                yield lines
                lines = []
        if lines:
            yield lines
#
def main():
#---------------------------------------------------
    start_time = time.time()  # 
    start_timetamp = datetime.now().strftime("%Y%m%d %H:%M:%S")
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        log.write(f"{start_timetamp} generate json started\n")
        
    
    #################BGPdumpjson
    
    now = datetime.now()-timedelta(hours=8)
    '''
    timestamp = now.strftime("%Y%m%d")
    bgpdumptimestamp=now.strftime("%Y%m%d")
    
    year=now.strftime("%Y")
    month=now.strftime("%m")
    day=now.strftime("%d")
    '''
    date = sys.argv[1].split('/')[0]
    year = date.split('-')[0]
    month = date.split('-')[1]
    day = date.split('-')[2]
    timestamp = year+month+day
    bgpdumptimestamp = timestamp
    num_of_chunk = 20 #
    counter_as_set=[0] #as set
    #----unreachable------------------------
    spemap4 = {}
    spemap6 = {}
    getspemap(spemap4, spemap6, pfxrov.special_pfx_list)
    
    #--------pch
    hourstamp = int(now.strftime("%H"))
    execu_hourstamp=hourstamp
    pch_log_file=f"{current_directory}/bgp_route/run-log/pch/log-pch-{timestamp}"
    if not os.path.exists(os.path.dirname(pch_log_file)):
        os.makedirs(os.path.dirname(pch_log_file))
    pch_collector_name_input=f"{current_directory}/bgp_route/ref/collector_list_name"
    
    cmd=f"rm -rf {current_directory}/bgp_route/analysis/blackhole/blackhole-{timestamp}"
    subprocess.check_output(cmd, shell=True, universal_newlines=True)

    
    
    with open(pch_log_file,'a') as log:
        log.write(f"------------------------------------------------pch-jsoutput-beign"+"\n")
        log.write(f"jsoutput-pch...{timestamp}-{execu_hourstamp}"+"\n")
    i=1
    ip_type=["4","6"]
    pch_collector_name = "['route-collector.dac.pch.net', 'route-collector.slc.pch.net', 'route-collector.mke.pch.net', 'route-collector.hre.pch.net', 'route-collector.decix-my2.jhb.pch.net', 'route-collector.akl.pch.net', 'route-collector.osl.pch.net', 'route-collector.franceix-mrs.pch.net', 'route-collector.per.pch.net', 'route-collector.dtm.pch.net', 'route-collector.los.pch.net', 'route-collector.msp.pch.net', 'route-collector.oua.pch.net', 'route-collector.str.pch.net', 'route-collector.equinix-dallas.dfw.pch.net', 'route-collector.evn.pch.net', 'route-collector.klu.pch.net', 'route-collector.pnh.pch.net', 'route-collector.megaport-mel.pch.net', 'route-collector.sge.pch.net', 'route-collector.hkg2.pch.net', 'route-collector.prg.pch.net', 'route-collector.sgu.pch.net', 'route-collector.decix-muc.fra.pch.net', 'route-collector.dvn.pch.net', 'route-collector.sjj.pch.net', 'route-collector.yxe.pch.net', 'route-collector.yia.pch.net', 'route-collector.kla.pch.net', 'route-collector.tie-phx.pch.net', 'route-collector.netnod-green-jumbo.arn.pch.net', 'route-collector.asu.pch.net', 'route-collector.qls.pch.net', 'route-collector.pap.pch.net', 'route-collector.aqj.pch.net', 'route-collector.jnb.pch.net', 'route-collector.ecix-fra.pch.net', 'route-collector.ach.pch.net', 'route-collector.rix.pch.net', 'route-collector.decix-lis.mad.pch.net', 'route-collector.dfw.pch.net', 'route-collector.locix.fra2.pch.net', 'route-collector.equinix-sg.pch.net', 'route-collector.tgu.pch.net', 'route-collector.mru.pch.net', 'route-collector.bgr.pch.net', 'route-collector.man.pch.net', 'route-collector.wlg.pch.net', 'route-collector.kbp.pch.net', 'route-collector.bjm.pch.net', 'route-collector.bey.pch.net', 'route-collector.fbm.pch.net', 'route-collector.lpb.pch.net', 'route-collector.szg.pch.net', 'route-collector.mle.pch.net', 'route-collector.otp.pch.net', 'route-collector.megaport-per.pch.net', 'route-collector.megaport-akl.pch.net', 'route-collector.mci.pch.net', 'route-collector.kbl.pch.net', 'route-collector.decix-jhb.jhb.pch.net', 'route-collector.ist.pch.net', 'route-collector.ecix-muc.fra.pch.net', 'route-collector.jib.pch.net', 'route-collector.decix-ham.fra.pch.net', 'route-collector.cak.pch.net', 'route-collector.amsix-sfo.pch.net', 'route-collector.asteroid-mba.pch.net', 'route-collector.lys.pch.net', 'route-collector.jpix.pch.net', 'route-collector.mex.pch.net', 'route-collector.tcix.pch.net', 'route-collector.bjl.pch.net', 'route-collector.ecix-dus.fra.pch.net', 'route-collector.pss.pch.net', 'route-collector.bwi2.pch.net', 'route-collector.ewr.pch.net', 'route-collector.edi.pch.net', 'route-collector.dxb.pch.net', 'route-collector.bom2.pch.net', 'route-collector.sdb.pch.net', 'route-collector.amsix-lga.pch.net', 'route-collector.aep.pch.net', 'route-collector.tpe.pch.net', 'route-collector.tpa.pch.net', 'route-collector.megaport-syd.pch.net', 'route-collector.tlv.pch.net', 'route-collector.jkt.pch.net', 'route-collector.kul.pch.net', 'route-collector.fogixp.ach2.pch.net', 'route-collector.ath.pch.net', 'route-collector.atl.pch.net', 'route-collector.nrt.pch.net', 'route-collector.lhr.pch.net', 'route-collector.gua.pch.net', 'route-collector.trn.pch.net', 'route-collector.gza.pch.net', 'route-collector.ccu.pch.net', 'route-collector.mdl.rgn.pch.net', 'route-collector.ord.pch.net', 'route-collector.cmh.pch.net', 'route-collector.ktm.pch.net', 'route-collector.zrh2.pch.net', 'route-collector.netnod-blue-jumbo.arn.pch.net', 'route-collector.phx.pch.net', 'route-collector.lux.pch.net', 'route-collector.jhb.pch.net', 'route-collector.wpgix.pch.net', 'route-collector.yqm.pch.net', 'route-collector.coo.pch.net', 'route-collector.vie.pch.net', 'route-collector.bos.pch.net', 'route-collector.lfw.pch.net', 'route-collector.dar.pch.net', 'route-collector.sbix.zrh3.pch.net', 'route-collector.decix-bcn.mad.pch.net', 'route-collector.lis.pch.net', 'route-collector.sna.pch.net', 'route-collector.decix-ruhr.fra.pch.net', 'route-collector.dla.pch.net', 'route-collector.decix-dus.fra.pch.net', 'route-collector.yow2.pch.net', 'route-collector.napafrica-jnb.pch.net', 'route-collector.lba.pch.net', 'route-collector.syd.pch.net', 'route-collector.cky.pch.net', 'route-collector.tun.pch.net', 'route-collector.tia.pch.net', 'route-collector.mba.pch.net', 'route-collector.fra.pch.net', 'route-collector.sjo.pch.net', 'route-collector.ndd.pch.net', 'route-collector.bwn.pch.net', 'route-collector-02.osl.pch.net', 'route-collector.ber.pch.net', 'route-collector.yyc.pch.net', 'route-collector.ric.pch.net', 'route-collector.pbm.pch.net', 'route-collector.mcix.pch.net', 'route-collector.sfo.pch.net', 'route-collector.chix-ch.ach2.pch.net', 'route-collector.mpm.pch.net', 'route-collector.skp.pch.net', 'route-collector.acc.pch.net', 'route-collector.ruh.pch.net', 'route-collector.bvy.pch.net', 'route-collector.fl-ix.mia.pch.net', 'route-collector.waw.pch.net', 'route-collector.nl-ix.pch.net', 'route-collector.kul2.pch.net', 'route-collector.ark.pch.net', 'route-collector.sof.pch.net', 'route-collector.fih.pch.net', 'route-collector.trd.pch.net', 'route-collector.tas.pch.net', 'route-collector.kwi.pch.net', 'route-collector.tll.pch.net', 'route-collector.pdx.pch.net', 'route-collector.megaport-sea.pch.net', 'route-collector.mnl2.pch.net', 'route-collector.cpt.pch.net', 'route-collector.akl2.pch.net', 'route-collector.linx-iad.pch.net', 'route-collector.kgl.pch.net', 'route-collector.pty.pch.net', 'route-collector.zdm.pch.net', 'route-collector.ham.pch.net', 'route-collector.icn.pch.net', 'route-collector.mia.pch.net', 'route-collector.boy.pch.net', 'route-collector.wdh.pch.net', 'route-collector.rno.pch.net', 'route-collector.gva.pch.net', 'route-collector.tie-ny.pch.net', 'route-collector.bom.pch.net', 'route-collector.dal.pch.net', 'route-collector.netnod-green.arn.pch.net', 'route-collector.pgz.pch.net', 'route-collector.gye.pch.net', 'route-collector.scl.pch.net', 'route-collector.lim.pch.net', 'route-collector.cmn.pch.net', 'route-collector.nbo.pch.net', 'route-collector.cmb.pch.net', 'route-collector.sea.pch.net', 'route-collector.ndj.pch.net', 'route-collector.fco.pch.net', 'route-collector.cdg.pch.net', 'route-collector.nsw-ix.pch.net', 'route-collector.qpg.pch.net', 'route-collector.rgn.pch.net', 'route-collector.gnd.pch.net', 'route-collector.megaport-sof.pch.net', 'route-collector.dac2.pch.net', 'route-collector.abj.pch.net', 'route-collector.pao.pch.net', 'route-collector.bko.pch.net', 'route-collector.plx.pch.net', 'route-collector.sju.pch.net', 'route-collector.den.pch.net', 'route-collector.bkk.pch.net', 'route-collector.hyd.pch.net', 'route-collector.lpb2.pch.net', 'route-collector.decix-ny.lga.pch.net', 'route-collector.paix-sea.pch.net', 'route-collector.slu.pch.net', 'route-collector.kef.pch.net', 'route-collector.rix-ams.pch.net', 'route-collector.megaport-yyz.pch.net', 'route-collector.tmp.pch.net', 'route-collector.iad.pch.net', 'route-collector.4ixp.zrh3.pch.net', 'route-collector.bzv.pch.net', 'route-collector.lbv.pch.net', 'route-collector.ywg.pch.net', 'route-collector.bwi.pch.net', 'route-collector.bur.pch.net', 'route-collector.stl.pch.net', 'route-collector.nixi.bom2.pch.net', 'route-collector.dtw.pch.net', 'route-collector.ams.pch.net', 'route-collector.fra2.pch.net', 'route-collector.espanix-mad.pch.net', 'route-collector.netix.pch.net', 'route-collector.megaport-bne.pch.net', 'route-collector.jax.pch.net', 'route-collector.yul.pch.net', 'route-collector.pbh.pch.net', 'route-collector.lad.pch.net', 'route-collector.zag.pch.net', 'route-collector.hkg.pch.net', 'route-collector.dur.pch.net', 'route-collector.mad.pch.net', 'route-collector.beg.pch.net', 'route-collector.arn.pch.net', 'route-collector.sxf.pch.net', 'route-collector.dub.pch.net', 'route-collector.lonap.pch.net', 'route-collector.yyz.pch.net', 'route-collector.amsix-ord.pch.net', 'route-collector.nyiix.pch.net', 'route-collector.mrs.pch.net', 'route-collector.yhz.pch.net', 'route-collector.zrh.pch.net', 'route-collector.mgm.pch.net', 'route-collector.bcn.pch.net', 'route-collector.soc.yia.pch.net', 'route-collector.ros.pch.net', 'route-collector.megaport-bur.pch.net', 'route-collector.decix-my.kul2.pch.net', 'route-collector.mgq.pch.net', 'route-collector.teraco-dur.pch.net', 'route-collector.sbh.pch.net', 'route-collector.lga.pch.net', 'route-collector.dod.pch.net', 'route-collector.decix-asean.kul2.pch.net', 'route-collector.blz.pch.net']"
    pch_collector_list=list(pch_collector_name.replace("'","").replace(",","").replace("[","").replace("]","").split())
    nums_per_process=len(pch_collector_list)//num_of_chunk
    print(f"{len(pch_collector_list)}")
    print(f"{nums_per_process}")
    remainder = len(pch_collector_list) % num_of_chunk  #  
    print(f"{remainder}")
    processid = 0
    collector_chunks = [pch_collector_list[i:i+nums_per_process] for i in range(0, len(pch_collector_list), nums_per_process)]
    #sys.exit(0)
    ts=[]
    for collector_chunk in collector_chunks:
        processid=processid+1
        t = multiprocessing.Process(target=pch_process, args=(ip_type,collector_chunk,year,month,day,timestamp,counter_as_set,processid,spemap4,spemap6))
        ts.append(t)
        # 
        t.start()   
    

    #print(f"processid={processid}")
    for i in ts:
        i.join()
    print(f"All processs finished.")
    #sys.exit(0)
    
    #--------ripe ris
    collector_seq=0
    hourstamp = int(now.strftime("%H"))
    execu_hourstamp=hourstamp
    if hourstamp>15:
        hourstamp="16"
    elif hourstamp<8:
        hourstamp='00'
    else:
        hourstamp="08"
    ripe_ris_log_file=f"{current_directory}/bgp_route/run-log/ripe_ris/log-bview-{timestamp}"
    if not os.path.exists(os.path.dirname(ripe_ris_log_file)):
        os.makedirs(os.path.dirname(ripe_ris_log_file))
    with open(ripe_ris_log_file,'a') as log:
        log.write(f"------------------------------------------------bview-download-beign"+"\n")
        log.write(f"jsoutput-bview...{timestamp}-{execu_hourstamp}"+"\n")
    collector_seq=0
    for seq_number in range(0,27):
        collector_seq+=1
        collector=f"rrc{seq_number}"
        if seq_number<10:
            seq_number=f"0{seq_number}"
        print(f"rrc{seq_number}========================================================================================================================================================================")
        inputname=f'{current_directory}/bgp_route/download/ripe_ris/bview.{timestamp}.0000.rrc{seq_number}.txt'
        if not os.path.exists(inputname) :
            print(f"{inputname}，rcc")
            continue
        with open(inputname, 'r') as input_file:
            read_seq=0
            for lines in read_file_by_lines(input_file,40000000):
                read_seq+=1
                if not lines:
                    break
                num_lines=len(lines)
                lines_per_process = num_lines // num_of_chunk
                print(f"{num_lines}")
                print(f"{lines_per_process}")
                remainder = num_lines % num_of_chunk  #  
                print(f"{remainder}")
                processid = 1
                if lines_per_process!=0 :
                    file_chunks = [lines[i:i+lines_per_process] for i in range(0, num_lines, lines_per_process)]
                    ts=[]
                    for chunk in file_chunks:
                        # ，
                        
                        t = multiprocessing.Process(target=process_file, args=(chunk,processid,timestamp,collector,read_seq,collector_seq,counter_as_set,spemap4,spemap6))
                        ts.append(t)
                        # 
                        t.start()   
                        processid=processid+1
                    for i in ts:
                        i.join()
                    print(f"All processs finished.")
                else :
                    if num_lines==0:
                        continue
                    print(f"{num_lines}，，")
                    chunk=lines[0:num_lines]
                    #print(chunk)
                    t = multiprocessing.Process(target=process_file, args=(chunk,processid,timestamp,collector,read_seq,collector_seq,counter_as_set,spemap4,spemap6))
                    t.start()
                    t.join()
                    processid=processid+1
    
    collector_seq=0
    routeview_collector_list = ["decix.jhb","route-views3","route-views4","route-views5","route-views6","decix.jhb",\
    "route-views.amsix","route-views.chicago","route-views.chile","route-views.eqix","route-views.flix",\
    "route-views.gorex","route-views.isc","route-views.kixp","route-views.jinx","route-views.linx","route-views.napafrica",\
    "route-views.nwax","pacwave.lax","route-views.phoix","route-views.telxatl","route-views.wide","route-views.sydney",\
    "route-views.saopaulo","route-views2.saopaulo","route-views.sg","route-views.perth","route-views.peru","route-views.sfmix",\
    "route-views.siex","route-views.soxrs","route-views.mwix","route-views.rio","route-views.fortaleza","route-views.gixa",\
    "route-views.bdix","route-views.bknix","route-views.uaeix","route-views.ny"]
    #collector_list = ["route-views.linx","decix.jhb","route-views3","route-views4","route-views5","route-views6","decix.jhb","route-views.amsix","route-views.chicago","route-views.chile","route-views.flix","route-views.gorex","route-views.isc","route-views.kixp","route-views.jinx","route-views.napafrica","route-views.nwax","pacwave.lax","route-views.phoix","route-views.telxatl","route-views.wide","route-views.sydney","route-views.saopaulo","route-views2.saopaulo","route-views.sg","route-views.perth","route-views.peru","route-views.sfmix","route-views.siex","route-views.soxrs","route-views.mwix","route-views.rio","route-views.fortaleza","route-views.gixa","route-views.bdix","route-views.bknix","route-views.uaeix","route-views.ny","route-views.eqix"]
    #--------routeviews rib
    for collector in routeview_collector_list:
        collector_seq+=1

        print(f"{collector}========================================================================================================================================================================")
        inputname=f'{current_directory}/bgp_route/download/routeview/bgpdump-output-{collector}.rib.{bgpdumptimestamp}.0000.txt'  
        if not os.path.exists(inputname) :
            print(f"{inputname}，collector")
            continue
        with open(inputname, 'r') as input_file:
            #  x ，
            
            #lines = input_file.readlines()
            #line_count=0
            #==========
            read_seq=0
            for lines in read_file_by_lines(input_file,40000000):
                read_seq+=1
                if not lines:
                    break
                num_lines=len(lines)
                lines_per_process = num_lines // num_of_chunk
                print(f"{num_lines}")
                print(f"{lines_per_process}")
                remainder = num_lines % num_of_chunk  #  
                print(f"{remainder}")
                processid = 1
                if lines_per_process!=0 :
                    file_chunks = [lines[i:i+lines_per_process] for i in range(0, num_lines, lines_per_process)]
                    ts=[]
                    for chunk in file_chunks:
                        # ，
                        t = multiprocessing.Process(target=process_file, args=(chunk,processid,timestamp,collector,read_seq,collector_seq,counter_as_set,spemap4,spemap6))
                        ts.append(t)
                        # 
                        t.start()   
                        processid=processid+1
                    for i in ts:
                        i.join()
                    print(f"All processs finished.")
                else :
                    if num_lines==0:
                        continue
                    print(f"{num_lines}，，")
                    chunk=lines[0:num_lines]
                    #print(chunk)
                    t = multiprocessing.Process(target=process_file, args=(chunk,processid,timestamp,collector,read_seq,collector_seq,counter_as_set,spemap4,spemap6))
                    t.start()
                    t.join()
                    processid=processid+1
    
    total_time=time.time()-start_time
    formatted_time = time.strftime("%H:%M:%S", time.gmtime(total_time))

    print(f"path path-output-collector-timestamp-processid 。")
    print(f"path：{formatted_time}")
    print(f"list list-output-collector-timestamp-processid 。")
    print(f"list：{formatted_time}")
    #----------------------------path
    print("total-path...")
    rib_total_path=f"{current_directory}/bgp_route/path/rib-total-path-{bgpdumptimestamp}"
    bview_total_path=f"{current_directory}/bgp_route/path/bview-total-path-{bgpdumptimestamp}"
    pch_total_path=f"{current_directory}/bgp_route/path/pch-total-path-{bgpdumptimestamp}"

    if not os.path.exists(os.path.dirname(rib_total_path)):
        os.makedirs(os.path.dirname(rib_total_path))
    if not os.path.exists(os.path.dirname(bview_total_path)):
        os.makedirs(os.path.dirname(bview_total_path))
    if not os.path.exists(os.path.dirname(pch_total_path)):
        os.makedirs(os.path.dirname(pch_total_path))

    with open(pch_total_path,'w') as output_path_total:
        file_seq=0
        path_total=[]
        path_temp=[]
        for type in ip_type:
            for collector in pch_collector_list:
                filename_path_to_check = f"{current_directory}/bgp_route/path/path-output-{collector}-ipv{type}-{timestamp}"
                #print(f"{filename_path_to_check}")
                if os.path.exists(filename_path_to_check):
                    file_seq+=1
                    #print(f"{file_seq}{filename_path_to_check}")
                    with open(filename_path_to_check,'r') as path_file:
                        #print(f"{path_file.readlines()}"+"/n")
                        path_temp=path_file.readline()
                        while path_temp:
                            #print(path_temp)
                            output_path_total.write(f"{path_temp.strip()}" +"\n")
                            path_temp=path_file.readline()
    
    with open(rib_total_path,'w') as output_path_total:
        file_seq=0
        path_total=[]
        path_temp=[]
        for collector in routeview_collector_list:
            file_seq+=1
            #print(file_seq)
            for read_seq in range(1,5):
                for processid in range(1,num_of_chunk+2):
                    filename_path_to_check = f"{current_directory}/bgp_route/path/path-output-{collector}-{bgpdumptimestamp}-{read_seq}-{processid}"
                    #print(f"{filenamIe_path_to_check}")
                    if os.path.exists(filename_path_to_check):
                        #print("exist")
                        #print(f"{file_seq}{filename_path_to_check}")
                        with open(filename_path_to_check,'r') as path_file:
                            #print(f"{path_file.readlines()}"+"/n")
                            path_temp=path_file.readline()
                            while path_temp:
                                #print(path_temp)
                                output_path_total.write(f"{path_temp.strip()}" +"\n")
                                path_temp=path_file.readline()
    with open(bview_total_path,'w') as output_path_total:
        file_seq=0
        for seq_number in range(0,27):
            file_seq+=1
            collector=f"rrc{seq_number}"
            for read_seq in range(1,5):
                for processid in range(1,num_of_chunk+2):
                    filename_path_to_check = f"{current_directory}/bgp_route/path/path-output-{collector}-{bgpdumptimestamp}-{read_seq}-{processid}"
                    #print(f"{filename_path_to_check}")
                    if os.path.exists(filename_path_to_check):
                        #print(f"{file_seq}{filename_path_to_check}")
                        with open(filename_path_to_check,'r') as path_file:
                            #print(f"{path_file.readlines()}"+"/n")
                            path_temp=path_file.readline()
                            while path_temp:
                                #print(path_temp)
                                output_path_total.write(f"{path_temp.strip()}" +"\n")
                                path_temp=path_file.readline()
    
    print("total-list...")
    filename_total_list=f"{current_directory}/bgp_route/list/total-list-{bgpdumptimestamp}"
    list_total=[]
    list_pch = []
    list_routeview = []
    list_ripe = []
    list_temp=[]
    file_seq=0
    
    for type in ip_type:
        for collector in pch_collector_list:
            file_seq+=1
            filename_list_to_check = f"{current_directory}/bgp_route/list/list-output-{collector}-ipv{type}-{timestamp}"
            #print(f"{filename_list_to_check}")
            if os.path.exists(filename_list_to_check):
                #print(f"{file_seq}{filename_list_to_check}")
                with open(filename_list_to_check,'r') as list_file:
                    #print(f"{list_file.readlines()}"+"/n")
                    list_temp=list_file.readline()
                    while list_temp:
                        #print(list_temp)
                        list_pch.append(list_temp.strip())
                        list_temp=list_file.readline()
    
    for collector in routeview_collector_list:
        file_seq+=1
        for read_seq in range(1,5):
            for processid in range(1,num_of_chunk+2):
                filename_list_to_check = f"{current_directory}/bgp_route/list/list-output-{collector}-{bgpdumptimestamp}-{read_seq}-{processid}"
                #print(f"{filename_list_to_check}")
                if os.path.exists(filename_list_to_check):
                    #print(f"{file_seq}{filename_list_to_check}")
                    with open(filename_list_to_check,'r') as list_file:
                        #print(f"{list_file.readlines()}"+"/n")
                        list_temp=list_file.readline()
                        while list_temp:
                            #print(list_temp)
                            list_routeview.append(list_temp.strip())
                            list_temp=list_file.readline()
                    #return
    for seq_number in range(0,27):
            file_seq+=1
            collector=f"rrc{seq_number}"
            for read_seq in range(1,5):
                for processid in range(1,num_of_chunk+2):
                    filename_list_to_check = f"{current_directory}/bgp_route/list/list-output-{collector}-{bgpdumptimestamp}-{read_seq}-{processid}"
                    #print(f"{filename_list_to_check}")
                    if os.path.exists(filename_list_to_check):
                        #print(f"{file_seq}{filename_list_to_check}")
                        with open(filename_list_to_check,'r') as list_file:
                            #print(f"{list_file.readlines()}"+"/n")
                            list_temp=list_file.readline()
                            while list_temp:
                                #print(list_temp)
                                list_ripe.append(list_temp.strip())
                                list_temp=list_file.readline()

    list_total_all = {}
    list_total_all['pch'] = list(set(list_pch))
    list_total_all['routeview'] = list(set(list_routeview))
    list_total_all['ripe'] = list(set(list_ripe))
    with open(filename_total_list,'w') as output_list_total:
        output_list_total.write(f"{list_pch}")
        output_list_total.write(f"{list_routeview}")
        output_list_total.write(f"{list_ripe}")

    filename_total_json=f"{current_directory}/bgp_route/checklog/total/total-json-{bgpdumptimestamp}.json"
    if not os.path.exists(os.path.dirname(filename_total_json)):
        os.makedirs(os.path.dirname(filename_total_json))
    route_dict3 = {
        "routes":[{
            "asn":0,
            "prefix":"0.0.0.0/0"
            }
        ]
    }

    count_list=0
    count_json=0
    route_dict3_nopch = {
            "routes":[{
                "asn":0,
                "prefix":"0.0.0.0/0"
                }
            ]
        }
    for key, item in list_total_all.items():
        list_total = item
        route_dict3_temp = {
            "routes":[{
                "asn":0,
                "prefix":"0.0.0.0/0"
                }
            ]
        }
        progress_bar = tqdm(list_total, desc=f'total-json', unit='route', unit_scale=True, leave=True,file=sys.stdout)
        for line in list_total:
            progress_bar.update(1)
            #print(list_total[i]+"\n")
            count_list+=1
            match = re.match(r'(\d{1,10}) (\d{1,3}(\.\d{1,3}){3}/\d{1,2}$)',line)
            if match :
                #print(line)
                #print(line+"\n")
                route={
                "asn":0,
                "prefix":"0.0.0.0/0"
                }
                route["asn"]=int(match.group(1))
                route["prefix"]=match.group(2)
                #print(route)
                route_dict3['routes'].append(route)
                route_dict3_temp['routes'].append(route)
                if key != 'pch':
                    route_dict3_nopch['routes'].append(route)
                count_json+=1      
            else :
                match = re.match(r'(\d{1,10}) ([0-9a-fA-F:]+/\d{1,3}$)',line)
                
                if not match:
                    print(line)
                    sys.exit(0)
                route={
                "asn":0,
                "prefix":"0.0.0.0/0"
                }
                route["asn"]=int(match.group(1))
                route["prefix"]=match.group(2)
                route_dict3['routes'].append(route)
                route_dict3_temp['routes'].append(route)
                if key != 'pch':
                    route_dict3_nopch['routes'].append(route)
                count_json+=1
        json_str = json.dumps(route_dict3_temp)
        #print(f"json_str={json_str}")
        filename_temp_json=f"{current_directory}/bgp_route/checklog/total/total-json-{bgpdumptimestamp}-{key}.json"
        with open(filename_temp_json,'w') as output_total_json:
            output_total_json.write(json_str)

    json_str = json.dumps(route_dict3_nopch)
    #print(f"json_str={json_str}")
    filename_temp_json=f"{current_directory}/bgp_route/checklog/total/total-json-{bgpdumptimestamp}-nopch.json"
    with open(filename_temp_json,'w') as output_total_json:
        output_total_json.write(json_str)

    print(count_list)
    #print("\n")
    print(count_json)
    json_str = json.dumps(route_dict3)
    #print(f"json_str={json_str}")
    with open(filename_total_json,'w') as output_total_json:
        output_total_json.write(json_str)
    print(f" total-json-bgpdumptimestamp.json。")
    with open(f"{current_directory}/bgp_route/run-log/log-{bgpdumptimestamp}",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        log.write(f"{finish_timestamp} json：{formatted_time},{current_directory}/bgp_route/checklog/total/validity-total-bgpdumptimestamp.json"+"\n")
        log.write(f"jsoutput.py！"+"\n")
        log.write(f"as-set{counter_as_set[0]}"+"\n")
    cmd_remove=f"rm -f {current_directory}/bgp_route/list/list-output*{timestamp}*"
    subprocess.check_output(cmd_remove, shell=True, universal_newlines=True)
    cmd_remove=f"rm -f {current_directory}/bgp_route/path/path-output*{timestamp}*"
    subprocess.check_output(cmd_remove, shell=True, universal_newlines=True)

    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_timestamp = datetime.now().strftime("%Y%m%d %H:%M:%S")
        duration = time.time() - start_time
        log.write(f"{finish_timestamp} generate json ended, used {duration} seconds\n")


    
if __name__ == '__main__':
    main()
