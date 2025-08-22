#!/bin/bash


CURRENT_MONTH=$(date +"%Y%m")

BASE_URL="https://publicdata.caida.org/datasets/as-relationships/serial-2/"
FILE_NAME="${CURRENT_MONTH}01.as-rel2.txt.bz2"
FILE_NAME_A="${CURRENT_MONTH}01.as-rel2.txt"
DOWNLOAD_DIR="/home/demo/multi_source_data/CAIDA/relationship/"



if [ -f "$DOWNLOAD_DIR/$FILE_NAME_A"  ]; then
    echo "Download finished, skip."
else
    if wget --spider "${BASE_URL}${FILE_NAME}" 2>/dev/null; then
        wget -P "$DOWNLOAD_DIR" "${BASE_URL}${FILE_NAME}"
        bzip2 -d "$DOWNLOAD_DIR/$FILE_NAME"
        cp "$DOWNLOAD_DIR/$FILE_NAME_A" "$DOWNLOAD_DIR/as-rel2.txt"
    fi
fi



BASE_URL="https://publicdata.caida.org/datasets/as-organizations/"
FILE_NAME="${CURRENT_MONTH}01.as-org2info.jsonl.gz"
FILE_NAME_A="${CURRENT_MONTH}01.as-org2info.jsonl"
DOWNLOAD_DIR="/home/demo/multi_source_data/CAIDA/as_org/"


if [ -f "$DOWNLOAD_DIR/$FILE_NAME_A"  ]; then
    echo "Download finished, skip."
else
    if wget --spider "${BASE_URL}${FILE_NAME}" 2>/dev/null; then
        wget -P "$DOWNLOAD_DIR" "${BASE_URL}${FILE_NAME}"
        gunzip "$DOWNLOAD_DIR/$FILE_NAME"
        cp "$DOWNLOAD_DIR/$FILE_NAME_A" "$DOWNLOAD_DIR/as-org2info.jsonl"
    fi
fi


BASE_URL="https://publicdata.caida.org/datasets/as-organizations/"
FILE_NAME="${CURRENT_MONTH}01.as-org2info.txt.gz"
FILE_NAME_A="${CURRENT_MONTH}01.as-org2info.txt"
DOWNLOAD_DIR="/home/demo/multi_source_data/CAIDA/as_org/"


if [ -f "$DOWNLOAD_DIR/$FILE_NAME_A"  ]; then
    echo "Download finished, skip."
else
    if wget --spider "${BASE_URL}${FILE_NAME}" 2>/dev/null; then
        wget -P "$DOWNLOAD_DIR" "${BASE_URL}${FILE_NAME}"
        gunzip "$DOWNLOAD_DIR/$FILE_NAME"
        cp "$DOWNLOAD_DIR/$FILE_NAME_A" "$DOWNLOAD_DIR/as-org2info.txt"
    fi
fi

