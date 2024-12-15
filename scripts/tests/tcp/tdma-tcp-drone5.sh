#!/bin/bash

# $1 - single, two, four, six
# $2 - a,b,c,d,e

cd .. # Tests Folder

cd .. # Scripts Folder

cd tcp_throughput_testing 

./test_throughput_drone5.sh

cd .. # Scripts Folder

cd .. # Root Folder

cd docs/logs

./save_log iperf-log-latest.txt tdma-tests $1-node-throughput drone5-$2