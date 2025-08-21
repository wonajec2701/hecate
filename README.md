# Hecate -- From Unknown to Known: Enhancing BGP Route Origin Validation with Multi-Source Data

## The latest validation results

### Comparison of CRO Validation Results with RPKI ROA and IRR

![](./data/figure/mdis_validate_compare_total.pdf.png)

### CRO Validation Results on the Global Routing Table

![](./data/figure/mdis_ipv4_ipv6.pdf.png)

### ROA Validation Results on the Global Routing Table

![](./data/figure/mdis_ipv4_ipv6_roa.pdf.png)

### CRO sources

![](./data/figure/mdis_CRO_sources.pdf.png)

## Locations of the CRO Data

The CRO data is stored in the `data/cro.gz` and `cro_new.gz` 

## Description of the code structure

The repo contains the following directories:

### Requirements

Routinator: https://routinator.docs.nlnetlabs.nl/en/stable/index.html#

Python3: https://www.python.org/downloads/

Python3 packages: tqdm

bgpdump:
```
For Ubuntu

sudo apt update
sudo apt install bgpdump
```


### Workflow
```
git clone https://github.com/wonajec2701/hecate.git
# if you cannot clone, please try:
# git clone --depth 1 https://github.com/wonajec2701/hecate.git
# git fetch --unshallow
mkdir /home/demo   # adduser demo
mv hecate/code/multi_source_data /home/demo/multi_source_data
# please replace YOUR_PASSWORD with your actual password below.
sed -i '5s/password=""/password="YOUR_PASSWORD"/' demo_start_bgp_roa.sh 
```
```
crontab -e
```
add next commands:
```
20 0 * * * /home/demo/multi_source_data/demo_start_bgp_roa.sh
10 1 * * * /home/demo/multi_source_data/demo_start_irr.sh
```
