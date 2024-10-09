#!/bin/bash

./add_qdisc.sh test-config-drone2
iperf3 -c 10.10.10.1 -t 60 -p 5202 > ../docs/logs/iperf-log-latest.txt
./remove_qdisc.sh wlx000f60050e55
