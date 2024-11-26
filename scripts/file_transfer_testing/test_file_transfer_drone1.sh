#!/bin/bash

cd .. #Scripts folder

./utils/add_qdisc.sh test-config-drone1
dd if=/dev/zero bs=1M count=250 | ssh pi@10.10.10.2 'dd of=/dev/null' 2>&1 | tee ../docs/logs/file-transfer-log.txt
./utils/remove_qdisc.sh wlan0
