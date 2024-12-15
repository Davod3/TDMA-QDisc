#!/bin/bash

# $1 - single, two, four, six
# $2 - a,b,c,d,e

cd .. # Tests Folder

cd .. # Scripts Folder

cd no_qdisc_testing 

./test_throughput_noqdisc_drone2.sh

cd .. # Scripts Folder

cd .. # Root Folder

cd docs/logs

./save_log.sh iperf-log-latest.txt csma-tests $1-node-throughput drone2-$2