#!/bin/bash

cd .. # Scripts Folder

./utils/add_qdisc.sh test-config-drone2
iperf3 -c 10.10.10.1 -t 60 -p 5201 -b 0 -u > ../docs/logs/iperf-log-latest.txt
./utils/remove_qdisc.sh wlan0
