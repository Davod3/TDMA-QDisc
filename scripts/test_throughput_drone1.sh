#!/bin/bash

./add_qdisc.sh test-config
iperf3 -c 192.168.4.1 -t 60 -p 5201 > ../docs/logs/iperf-log-latest.txt
./remove_qdisc.sh wlo1