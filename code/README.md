# Hecate Code

## Requirements

Routinator https://routinator.docs.nlnetlabs.nl/en/stable/index.html#

Python3 https://www.python.org/downloads/

bgpdump
```
Ubuntu

sudo apt update
sudo apt install bgpdump
```

## Workflow
```
git clone https://github.com/wonajec2701/hecate.git
mkdir /home/demo # adduser demo
mv hecate/code/multi_source_data /home/demo/multi_source_data
```
```
crontab -e
```
add next commands:
```
20 0 * * * /home/demo/multi_source_data/start_bgp_roa.sh
10 1 * * * /home/demo/multi_source_data/start.sh
```