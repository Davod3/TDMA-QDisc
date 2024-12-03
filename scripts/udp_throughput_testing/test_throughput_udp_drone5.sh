#!/bin/bash

cd .. # Scripts FOlder

./utils/add_qdisc.sh test-config-drone5
iperf3 -c 10.10.10.6 -t 60 -p 5201 -b 0 -u > ../docs/logs/iperf-log-latest.txt
./utils/remove_qdisc.sh wlan0
