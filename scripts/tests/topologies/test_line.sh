#!/bin/bash

# $1 - Node ID

cd .. # Tests Folder

cd .. # Scripts Folder

sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.wlan0.send_redirects=0

test_duration_s=60
test_guard_s=$((test_duration_s + 25))
initial_offset_s=10

#Array to store iperf3 process ids
pids=()

echo "Starting..."

sudo dmesg -C

sudo dmesg -w | grep -E '\[TDMA ROUND\]|\[DELAY\]|\[OFFSET\]|\[TOTAL OFFSET\]|\[SLOT_START\]|\[SLOT_END\]|\[PARENT\]|\[SLOT_ID\]|\[DELAY_ON\]|\[DELAY_OFF\]|\[RECEIVED_PACKET\]' > ../docs/logs/kernel-log-latest.txt &

if [ $1 -eq '1' ]; then

    #Block packets from grandchildren nodes
    ./topology_utils/block_node3.sh

    #Add multihop routes to grandchildren nodes
    sudo route add -host 10.10.10.3 gw 10.10.10.2 wlan0

    ./utils/add_qdisc.sh test-config-drone$1

    sleep $initial_offset_s

    iperf3 -c 10.10.10.3 -t $test_duration_s -p 5201 -u &
    pids+=($!)

    #Fill logs with nothing
    echo "None" > ../docs/logs/iperf-log-latest.txt

    # Wait for iperf3 clients to finish transmitting
    for pid in "${pids[@]}"; do
        wait "$pid"
    done

    #Sleep goes here
    #sleep $test_guard_s

    ./utils/remove_qdisc.sh wlan0

    #Remove new routes
    sudo ip route del 10.10.10.3

    #Remove blocking
    ./topology_utils/unblock_node3.sh

fi

if [ $1 -eq '2' ]; then

    ./utils/add_qdisc.sh test-config-drone$1

    #Fill logs with nothing
    echo "None" > ../docs/logs/iperf-log-latest.txt

    #Sleep goes here
    sleep $test_guard_s

    ./utils/remove_qdisc.sh wlan0

fi

if [ $1 -eq '3' ]; then
    
    ./topology_utils/block_node1.sh

    sudo route add -host 10.10.10.1 gw 10.10.10.2 wlan0

    ./utils/add_qdisc.sh test-config-drone$1

    #Fill logs with nothing
    echo "None" > ../docs/logs/iperf-log-latest.txt

    #Sleep goes here
    sleep $test_guard_s

    ./utils/remove_qdisc.sh wlan0

    sudo ip route del 10.10.10.1

    ./topology_utils/unblock_node1.sh

fi

cd .. # Root Folder

cd docs/logs

sudo pkill -f 'dmesg -w'

./save_log.sh kernel-log-latest.txt line-topology tdma drone$1
./save_log.sh iperf-log-latest.txt line-topology tdma drone$1-throughput

sudo sysctl -w net.ipv4.conf.all.send_redirects=1
sudo sysctl -w net.ipv4.conf.wlan0.send_redirects=1