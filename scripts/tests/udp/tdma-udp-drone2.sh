#!/bin/bash

# $1 - single, two, four, six
# $2 - a,b,c,d,e

cd .. # Tests Folder

cd .. # Scripts Folder

cd udp_throughput_testing 

./test_throughput_udp_drone2.sh

cd .. # Scripts Folder

cd .. # Root Folder

cd docs/logs

./save_log iperf-log-latest.txt tdma-tests $1-node-throughput-udp drone2-$2