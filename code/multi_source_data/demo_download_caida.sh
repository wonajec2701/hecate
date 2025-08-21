#!/bin/bash


CURRENT_MONTH=$(date +"%Y%m")

# 设置变量
BASE_URL="https://publicdata.caida.org/datasets/as-relationships/serial-2/"
FILE_NAME="${CURRENT_MONTH}01.as-rel2.txt.bz2"
FILE_NAME_A="${CURRENT_MONTH}01.as-rel2.txt"
DOWNLOAD_DIR="/home/demo/multi_source_data/CAIDA/relationship/"  # 指定下载目录


# 检查是否已下载
if [ -f "$DOWNLOAD_DIR/$FILE_NAME_A"  ]; then
    echo "本月文件已下载，跳过下载。"
else
    # 检查文件是否存在
    if wget --spider "${BASE_URL}${FILE_NAME}" 2>/dev/null; then
        # 如果文件存在，则下载
        wget -P "$DOWNLOAD_DIR" "${BASE_URL}${FILE_NAME}"
        # 解压文件
        bzip2 -d "$DOWNLOAD_DIR/$FILE_NAME"
        cp "$DOWNLOAD_DIR/$FILE_NAME_A" "$DOWNLOAD_DIR/as-rel2.txt"
    fi
fi




# 设置变量
BASE_URL="https://publicdata.caida.org/datasets/as-organizations/"
FILE_NAME="${CURRENT_MONTH}01.as-org2info.jsonl.gz"
FILE_NAME_A="${CURRENT_MONTH}01.as-org2info.jsonl"
DOWNLOAD_DIR="/home/demo/multi_source_data/CAIDA/as_org/"  # 指定下载目录


# 检查是否已下载
if [ -f "$DOWNLOAD_DIR/$FILE_NAME_A"  ]; then
    echo "本月文件已下载，跳过下载。"
else
    # 检查文件是否存在
    if wget --spider "${BASE_URL}${FILE_NAME}" 2>/dev/null; then
        # 如果文件存在，则下载
        wget -P "$DOWNLOAD_DIR" "${BASE_URL}${FILE_NAME}"
        # 解压文件
        gunzip "$DOWNLOAD_DIR/$FILE_NAME"
        cp "$DOWNLOAD_DIR/$FILE_NAME_A" "$DOWNLOAD_DIR/as-org2info.jsonl"
    fi
fi


# 设置变量
BASE_URL="https://publicdata.caida.org/datasets/as-organizations/"
FILE_NAME="${CURRENT_MONTH}01.as-org2info.txt.gz"
FILE_NAME_A="${CURRENT_MONTH}01.as-org2info.txt"
DOWNLOAD_DIR="/home/demo/multi_source_data/CAIDA/as_org/"  # 指定下载目录


# 检查是否已下载
if [ -f "$DOWNLOAD_DIR/$FILE_NAME_A"  ]; then
    echo "本月文件已下载，跳过下载。"
else
    # 检查文件是否存在
    if wget --spider "${BASE_URL}${FILE_NAME}" 2>/dev/null; then
        # 如果文件存在，则下载
        wget -P "$DOWNLOAD_DIR" "${BASE_URL}${FILE_NAME}"
        # 解压文件
        gunzip "$DOWNLOAD_DIR/$FILE_NAME"
        cp "$DOWNLOAD_DIR/$FILE_NAME_A" "$DOWNLOAD_DIR/as-org2info.txt"
    fi
fi

