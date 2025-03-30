#!/bin/bash

# $1 - Node ID

cd .. # Tests Folder

cd .. # Scripts Folder

#Array to store iperf3 process ids
pids=()

parent_node=1

sudo dmesg -C

sudo dmesg -w | grep -E '\[TDMA ROUND\]|\[DELAY\]|\[OFFSET\]|\[TOTAL OFFSET\]|\[SLOT_START\]|\[SLOT_END\]|\[PARENT\]|\[SLOT_ID\]|\[DELAY_ON\]|\[DELAY_OFF\]|\[RECEIVED_PACKET\]' > ../docs/logs/kernel-log-latest.txt &

./utils/add_qdisc.sh test-config-drone$1

if [ $1 -eq $parent_node ]
then
    iperf3 -c 10.10.10.2 -t 60 -p 5201 -b 0 -u &
    pids+=($!)
        
    iperf3 -c 10.10.10.3 -t 60 -p 5201 -b 0 -u &
    pids+=($!)

    iperf3 -c 10.10.10.4 -t 60 -p 5201 -b 0 -u &
    pids+=($!)

    iperf3 -c 10.10.10.5 -t 60 -p 5201 -b 0 -u &
    pids+=($!)

    iperf3 -c 10.10.10.6 -t 60 -p 5201 -b 0 -u &
    pids+=($!)

else
    iperf3 -c 10.10.10.1 -t 60 -p 520$1 -b 0 -u > ../docs/logs/iperf-log-latest.txt
fi

# Wait for iperf3 clients to finish transmitting
for pid in "${pids[@]}"; do
    wait "$pid"
done

./utils/remove_qdisc.sh wlan0

cd .. # Root Folder

cd docs/logs

sudo pkill -f 'dmesg -w'

./save_log.sh kernel-log-latest.txt star-topology tdma drone$1-kernel
./save_log.sh iperf-log-latest.txt star-topology tdma drone$1-throughput