#!/bin/bash

cd .. # Scripts Folder

./utils/add_qdisc.sh test-config-drone1
iperf3 -c 10.10.10.2 -t 60 -p 5201 > ../docs/logs/iperf-log-latest.txt
./utils/remove_qdisc.sh wlan0