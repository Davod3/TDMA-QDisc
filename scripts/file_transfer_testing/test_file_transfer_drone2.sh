#!/bin/bash

cd .. #Scripts folder

./utils/add_qdisc.sh test-config-drone2
dd if=/dev/zero bs=1M count=250 | ssh pi@10.10.10.1 'dd of=/dev/null' 2>&1 | tee ../docs/logs/file-transfer-log.txt
./utils/remove_qdisc.sh wlan0
