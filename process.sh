#!/bin/bash

cd /home/demo/hecate/
cp ../multi_source_data/cro_data/cro_new.json .
rm cro_new.json.gz
gzip cro_new.json
cp ../multi_source_data/data/figure/mdis_CRO_sources.pdf data/figure/
cp ../multi_source_data/data/figure/mdis_ipv4_ipv6_roa.pdf data/figure/
cp ../multi_source_data/data/figure/mdis_ipv4_ipv6.pdf data/figure/
cp ../multi_source_data/data/figure/mdis_tal.pdf data/figure/
cp ../multi_source_data/data/figure/mdis_validate_compare_ipv4.pdf data/figure/
cp ../multi_source_data/data/figure/mdis_validate_compare_ipv6.pdf data/figure/
cp ../multi_source_data/data/figure/mdis_validate_compare_total.pdf data/figure/
cp ../multi_source_data/data/result/mdis_CRO_analysis data/result/
cp ../multi_source_data/data/cro data/
cd data
rm cro.gz
gzip cro
cd ..


cd data/figure
ls | xargs -i convert {} {}.png
cd ..

current_date=$(date +%Y-%m-%d)
git add .
git commit -m "$current_date"
git push -u origin main