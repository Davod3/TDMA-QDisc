#!/bin/bash

# $1 - Node Number

cd .. # Tests Folder

cd .. # Scripts Folder

cd udp_throughput_testing

sudo dmesg -C

sudo dmesg -w | grep -E '\[TDMA ROUND\]|\[DELAY\]' > ../../docs/logs/kernel-log-latest.txt &

./test_throughput_udp_drone$1.sh

cd .. # Scripts Folder

cd .. # Root Folder

cd docs/logs

sudo pkill -f 'dmesg -w'

./save_log.sh kernel-log-latest.txt ratdma-sync 2nodes-5seconds drone$1
