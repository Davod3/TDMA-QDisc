#!/bin/bash

./add_qdisc.sh test-config-rpi
ping 192.168.4.31
./remove_qdisc.sh wlan0
