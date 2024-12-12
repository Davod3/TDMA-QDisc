#!/bin/bash

cd .. # Scripts Folder

./utils/add_qdisc.sh test-config-drone5
iperf3 -c 10.10.10.6 -t 900 -p 5201 -b 0 -u > ../docs/logs/iperf-log-latest.txt &

for ((i=0; i<90; i++))
do
    #Sample NTP stats
    ntpstat | grep 'time correct to' | sed -n 's/.* \([0-9]\+\) ms.*/\1/p' >> ../docs/logs/ntpstat-log.txt
    sleep 10
done

./utils/remove_qdisc.sh wlan0