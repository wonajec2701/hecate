#!/bin/python3

import sys
import concurrent.futures

def main(args):
    input_file_name, output_dir = args
    print("input file name:", input_file_name)
    file = open(input_file_name, 'r', encoding='ISO-8859-1')
    data = file.read()
    sections = data.strip().split('\n\n')
    print(len(sections))

    old_name = sections[0].split(':')[0]
    type_start = [[old_name, 0]]

    count = 0
    for i in range(1, len(sections)):
        new_name = sections[i].split(':')[0]
        if new_name != old_name:
            last_start = type_start[-1][1]
            if len(old_name) <= 15 and not old_name.startswith('#'):
                output_file = open(output_dir + "/db." + old_name, 'a', encoding='ISO-8859-1')
                output_file.write('\n\n'.join(sections[last_start:i]) + '\n\n')
                #print(old_name, last_start, i-1)
            type_start.append([new_name, i])
            old_name = new_name

    last_start = type_start[-1][1]
    if len(old_name) <= 15 and not old_name.strip().startswith('#'):
        output_file = open(output_dir + "/db." + old_name, 'a', encoding='ISO-8859-1')
        output_file.write('\n\n'.join(sections[last_start:len(sections)]) + '\n\n')
        #print(old_name, last_start, len(sections)-1)



if __name__ == "__main__":
    args = sys.argv[1:]
    main(args)
