#!/bin/bash

./add_qdisc.sh test-config-rpi
iperf3 -c 192.168.4.1 -t 60 -p 5202 > ../docs/logs/iperf-log-latest.txt
./remove_qdisc.sh wlan0
