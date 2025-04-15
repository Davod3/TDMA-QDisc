#!/bin/bash

# $1 - Node ID

cd .. # Tests Folder

cd .. # Scripts Folder

if [ $1 -eq '1' ]; then

    #Block packets from grandchildren nodes
    ./topology_utils/block_node4.sh
    ./topology_utils/block_node5.sh
    ./topology_utils/block_node6.sh

    #Add multihop routes to grandchildren nodes
    sudo route add -host 10.10.10.4 gw 10.10.10.2 wlan0
    sudo route add -host 10.10.10.5 gw 10.10.10.2 wlan0
    sudo route add -host 10.10.10.6 gw 10.10.10.3 wlan0

    #iperf3 -c 10.10.10.1 -t 60 -p 520$1 -b 0 -u > ../docs/logs/iperf-log-latest.txt

    #Check routes with tracepath
    tracepath -4 10.10.10.1
    tracepath -4 10.10.10.2
    tracepath -4 10.10.10.3
    tracepath -4 10.10.10.4
    tracepath -4 10.10.10.5
    tracepath -4 10.10.10.6

    #Remove new routes
    sudo ip route del 10.10.10.4
    sudo ip route del 10.10.10.5
    sudo ip route del 10.10.10.6

    #Remove blocking
    ./topology_utils/unblock_node4.sh
    ./topology_utils/unblock_node5.sh
    ./topology_utils/unblock_node6.sh


fi

if [ $1 -eq '2' ]; then
    
    ./topology_utils/block_node3.sh
    ./topology_utils/block_node6.sh

    sudo route add -host 10.10.10.3 gw 10.10.10.1 wlan0
    sudo route add -host 10.10.10.6 gw 10.10.10.1 wlan0

    #Check routes with tracepath
    tracepath -4 10.10.10.1
    tracepath -4 10.10.10.2
    tracepath -4 10.10.10.3
    tracepath -4 10.10.10.4
    tracepath -4 10.10.10.5
    tracepath -4 10.10.10.6

    sudo ip route del 10.10.10.3
    sudo ip route del 10.10.10.6

    ./topology_utils/unblock_node3.sh
    ./topology_utils/unblock_node6.sh

fi

if [ $1 -eq '3' ]; then
    
    ./topology_utils/block_node2.sh
    ./topology_utils/block_node4.sh
    ./topology_utils/block_node5.sh

    sudo route add -host 10.10.10.2 gw 10.10.10.1 wlan0
    sudo route add -host 10.10.10.4 gw 10.10.10.1 wlan0
    sudo route add -host 10.10.10.5 gw 10.10.10.1 wlan0

    #Check routes with tracepath
    tracepath -4 10.10.10.1
    tracepath -4 10.10.10.2
    tracepath -4 10.10.10.3
    tracepath -4 10.10.10.4
    tracepath -4 10.10.10.5
    tracepath -4 10.10.10.6

    sudo ip route del 10.10.10.2
    sudo ip route del 10.10.10.4
    sudo ip route del 10.10.10.5

    ./topology_utils/unblock_node2.sh
    ./topology_utils/unblock_node4.sh
    ./topology_utils/unblock_node5.sh

fi

if [ $1 -eq '4' ]; then

    ./topology_utils/block_node5.sh
    ./topology_utils/block_node1.sh
    ./topology_utils/block_node3.sh
    ./topology_utils/block_node6.sh

    sudo route add -host 10.10.10.5 gw 10.10.10.2 wlan0
    sudo route add -host 10.10.10.1 gw 10.10.10.2 wlan0
    sudo route add -host 10.10.10.3 gw 10.10.10.2 wlan0
    sudo route add -host 10.10.10.6 gw 10.10.10.2 wlan0

    #Check routes with tracepath
    tracepath -4 10.10.10.1
    tracepath -4 10.10.10.2
    tracepath -4 10.10.10.3
    tracepath -4 10.10.10.4
    tracepath -4 10.10.10.5
    tracepath -4 10.10.10.6

    sudo ip route del 10.10.10.5
    sudo ip route del 10.10.10.1
    sudo ip route del 10.10.10.3
    sudo ip route del 10.10.10.6

    ./topology_utils/unblock_node5.sh
    ./topology_utils/unblock_node1.sh
    ./topology_utils/unblock_node3.sh
    ./topology_utils/unblock_node6.sh

fi

if [ $1 -eq '5' ]; then
    
    ./topology_utils/block_node1.sh
    ./topology_utils/block_node4.sh
    ./topology_utils/block_node3.sh
    ./topology_utils/block_node6.sh

    sudo route add -host 10.10.10.1 gw 10.10.10.2 wlan0
    sudo route add -host 10.10.10.4 gw 10.10.10.2 wlan0
    sudo route add -host 10.10.10.3 gw 10.10.10.2 wlan0
    sudo route add -host 10.10.10.6 gw 10.10.10.2 wlan0

    #Check routes with tracepath
    tracepath -4 10.10.10.1
    tracepath -4 10.10.10.2
    tracepath -4 10.10.10.3
    tracepath -4 10.10.10.4
    tracepath -4 10.10.10.5
    tracepath -4 10.10.10.6

    sudo ip route del 10.10.10.1
    sudo ip route del 10.10.10.4
    sudo ip route del 10.10.10.3
    sudo ip route del 10.10.10.6

    ./topology_utils/unblock_node1.sh
    ./topology_utils/unblock_node4.sh
    ./topology_utils/unblock_node3.sh
    ./topology_utils/unblock_node6.sh


fi

if [ $1 -eq '6' ]; then
    
    ./topology_utils/block_node1.sh
    ./topology_utils/block_node2.sh
    ./topology_utils/block_node4.sh
    ./topology_utils/block_node5.sh

    sudo route add -host 10.10.10.1 gw 10.10.10.3 wlan0
    sudo route add -host 10.10.10.2 gw 10.10.10.3 wlan0
    sudo route add -host 10.10.10.4 gw 10.10.10.3 wlan0
    sudo route add -host 10.10.10.5 gw 10.10.10.3 wlan0

    #Check routes with tracepath
    tracepath -4 10.10.10.1
    tracepath -4 10.10.10.2
    tracepath -4 10.10.10.3
    tracepath -4 10.10.10.4
    tracepath -4 10.10.10.5
    tracepath -4 10.10.10.6

    sudo ip route del 10.10.10.1
    sudo ip route del 10.10.10.2
    sudo ip route del 10.10.10.4
    sudo ip route del 10.10.10.5

    ./topology_utils/unblock_node1.sh
    ./topology_utils/unblock_node2.sh
    ./topology_utils/unblock_node4.sh
    ./topology_utils/unblock_node5.sh

fi

cd .. # Root Folder

cd docs/logs

#./save_log.sh iperf-log-latest.txt star-topology csma drone$1-throughput