#!/bin/bash

cd .. # Scripts Folder

./utils/add_qdisc.sh test-config-drone2
ping 10.10.10.1
./utils/remove_qdisc.sh wlan0
