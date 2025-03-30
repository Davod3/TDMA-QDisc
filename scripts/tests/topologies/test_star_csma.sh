#!/bin/bash

# $1 - Node ID

cd .. # Tests Folder

cd .. # Scripts Folder

#Array to store iperf3 process ids
pids=()

parent_node=1

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

cd .. # Root Folder

cd docs/logs

./save_log.sh iperf-log-latest.txt star-topology csma drone$1-throughput