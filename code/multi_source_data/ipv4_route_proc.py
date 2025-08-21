import ipaddress
import concurrent.futures

# Function to convert IPv4 address range to CIDR notation
def convert_to_cidr(start, end):
    start_ip = ipaddress.IPv4Address(start)
    end_ip = ipaddress.IPv4Address(end)
    prefix = start_ip
    start_ip = int(start_ip)
    end_ip = int(end_ip)
    
    # Calculate the prefix length by counting the number of common bits in the start and end IPs
    common_bits = start_ip ^ end_ip
    prefix_length = 32 - common_bits.bit_length()
    
    cidr = f"{prefix}/{prefix_length}"
    return cidr

# Function to process a chunk of sections and return the results
def process_chunk(chunk):
    results = []
    for section in chunk:
        lines = section.strip().split('\n')
        if not lines[0].startswith("route:"):
            continue
        route = ""
        origin = ""
        source = ""

        for line in lines[1:]:
            if line.startswith("origin:"):
                try:
                    origin = line[7:].strip().split()[0]
                except:
                    pass
                break
        for line in lines[1:]:
            if line.startswith("source:"):
                try:
                    source = line[7:].strip().split()[0]
                except:
                    pass
                break
        try:
            asn = origin[2:]
            prefix = lines[0].split()
        except:
            continue
        if len(prefix) == 1:
            print(prefix)
        route = asn + ' ' + prefix[1] + ' ' + source
        results.append(route)
    return results

# Main function
def main(input_file, output_file, chunk_size=1000):
    with open(input_file, 'r', encoding='ISO-8859-1') as f:
        data = f.read()

    sections = data.strip().split('\n\n')

    # Divide sections into chunks
    chunks = [sections[i:i + chunk_size] for i in range(0, len(sections), chunk_size)]

    # Use ThreadPoolExecutor to process chunks in parallel
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(process_chunk, chunks))

    # Flatten the results list
    results = [cidr for chunk_result in results for cidr in chunk_result]

    print("result aquired! now reduce repetitons!")
    results = list(set(results))

    # Write the converted data to the output file in larger batches
    with open(output_file, 'w') as f:
        f.writelines('\n'.join(results))

if __name__ == "__main__":
    input_file = "db.route.uni"
    output_file = "irr-route"

    main(input_file, output_file)

