#!/bin/bash

cd .. # Scripts Folder

./utils/add_qdisc.sh test-config-drone1
ping 10.10.10.2
./utils/remove_qdisc.sh wlan0
