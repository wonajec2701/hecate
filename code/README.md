# Hecate Code

## Requirements

Routinator: https://routinator.docs.nlnetlabs.nl/en/stable/index.html#

Python3: https://www.python.org/downloads/

Python3 packages: tqdm

bgpdump:
```
For Ubuntu

sudo apt update
sudo apt install bgpdump
```


## Workflow
```
git clone https://github.com/wonajec2701/hecate.git
mkdir /home/demo # adduser demo
mv hecate/code/multi_source_data /home/demo/multi_source_data
# please replace YOUR_PASSWORD with your actual password below.
sed -i '5s/password=""/password="YOUR_PASSWORD"/' demo_start_bgp_roa.sh 
```

### For daily CRO:
```
crontab -e
```
add next commands:
```
20 0 * * * /home/demo/multi_source_data/demo_start_bgp_roa.sh
10 1 * * * /home/demo/multi_source_data/demo_start_irr.sh
```

Daily CRO File: 
```
/home/demo/multi_source_data/cro_data/cro_new.json
```