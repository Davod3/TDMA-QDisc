#!/bin/bash

./add_qdisc.sh test-config-drone1
iperf3 -c 10.10.10.2 -t 60 -p 5201 -b 0 -u > ../docs/logs/iperf-log-latest.txt
./remove_qdisc.sh wlx000f600580e1
