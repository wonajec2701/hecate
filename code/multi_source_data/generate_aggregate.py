from datetime import datetime, timedelta
import sys
import copy
import addr
import json
import time
import netaddr
import ipaddress
import multiprocessing
current_directory = sys.argv[1]
content = sys.argv[2]

def roa_aggregate_split(lock, data_asn, data, data_aggregate):
    for key in data_asn:
        for maxlen in data_asn[key]:
            networks = []
            temp_list = copy.deepcopy(data_asn[key][maxlen])
            for prefix in data_asn[key][maxlen]:
                networks.append(prefix)
            new_networks = netaddr.cidr_merge(networks)
            for temp in new_networks:
                temp_list_1 = copy.deepcopy(temp_list)
                prefix = str(temp)
                asn = int(key)
                maxLength = int(maxlen)
                initial_prefixs = []
                for initial_prefix in temp_list:
                    if ipaddress.ip_address(initial_prefix.split('/')[0]) in ipaddress.ip_network(temp):
                        initial_prefixs.append((initial_prefix, asn, maxLength))
                        temp_list_1.remove(initial_prefix)
                temp_list = copy.deepcopy(temp_list_1)
                if len(initial_prefixs) > 1:
                    lock.acquire()
                    try:
                        if (prefix, asn, maxLength) not in data and (prefix, asn, maxLength) not in data_aggregate:
                            data_aggregate[(prefix, asn, maxLength)] = {}
                            data_aggregate[(prefix, asn, maxLength)]['type'] = ['roa_aggregate']
                    finally:
                        lock.release()

def roa_aggregate(data_asn, data, content):
    if '67' in content:
        filename = current_directory + "/source_data/roa_aggregate_" + current_directory + "_" + content
    else:
        filename = current_directory + "/source_data/roa_aggregate_" + current_directory 
    data_aggregate = {}
    print(filename)
    print("first time, write")

    #process aggregate
    
    process_num = 20
    manager = multiprocessing.Manager()
    data_aggregate = manager.dict()
    lock = manager.Lock()
    
    keys = list(data_asn.keys())
    keys_per_group = len(keys) // process_num
    ts = []
    for i in range(process_num):
        start = i * keys_per_group
        end = (i + 1) * keys_per_group
        group_keys = keys[start:end]
        group_dict = {key: data_asn[key] for key in group_keys}
        t = multiprocessing.Process(target=roa_aggregate_split, args=(lock, group_dict, data, data_aggregate))
        ts.append(t)
        # 
        t.start()
    for i in ts:
        i.join()

    
    f = open(filename, 'w')
    for key in data_aggregate:
        f.write(str(key[1]) + ' ' + key[0] + ' ' + str(key[2]) + '\n')
    f.close()
    return data_aggregate


def read_CRO(file):
    f1 = open(file, 'r')
    print(file)
    data = {}
    data_asn = {}
    for line in f1:
        if "asn" not in line:
            continue
        asn = int(line.split("asn\": \"")[1].split("\"")[0][2:])
        prefix = line.split("prefix\": \"")[1].split("\"")[0]
        maxLength = int(line.split("maxLength\": ")[1].split(",")[0])
        ty_pe = line.split("type\": \"")[1].split("\"")[0]
        talist = line.split("tal\": \"")[1].split("\"")[0]

        if (prefix, asn, maxLength) not in data:
            data[(prefix, asn, maxLength)] = {}
            data[(prefix, asn, maxLength)]['source'] = ty_pe
            data[(prefix, asn, maxLength)]['valid'] = []
            data[(prefix, asn, maxLength)]['invalid'] = []
        
        if asn not in data_asn:
            data_asn[asn] = {}
            data_asn[asn][maxLength] = [prefix]
        else:
            if maxLength not in data_asn[asn]:
                data_asn[asn][maxLength] = [prefix]
            else:
                data_asn[asn][maxLength].append(prefix)

    f1.close()
    return data, data_asn

def main():
    if '67' in content:
        cro_file = "/home/demo/multi_source_data/" + current_directory + "/cro_data/cro_mdis_initial_" + current_directory + "_" + content
    else:
        cro_file = "/home/demo/multi_source_data/" + current_directory + "/cro_data/cro_mdis_initial_" + current_directory
    

    start_time = datetime.now()
    start_timetamp = start_time.strftime("%Y%m%d %H:%M:%S")
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        log.write(f"{content}: {current_directory} cro aggregate started\n")

    data_cro, data_cro_asn = read_CRO(cro_file)
    data_aggregate = roa_aggregate(data_cro_asn, data_cro, content)
    with open(f"{current_directory}/execution_log.txt",'a') as log:
        finish_time = datetime.now()
        finish_timestamp = finish_time.strftime("%Y%m%d %H:%M:%S")
        total_num = len(data_aggregate)
        log.write(f"{content}: {finish_timestamp} cro aggregate ended, added {total_num} aggregated records.\n")

if __name__ == "__main__":
    main()