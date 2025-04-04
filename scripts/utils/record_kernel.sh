# $1 - Node Number

cd .. #Scripts Folder

cd .. # Root Folder

sudo dmesg -C

sudo dmesg -w | grep -E '\[TDMA ROUND\]|\[DELAY\]|\[OFFSET\]|\[TOTAL OFFSET\]|\[SLOT_START\]|\[SLOT_END\]|\[PARENT\]|\[SLOT_ID\]|\[DELAY_ON\]|\[DELAY_OFF\]|\[RECEIVED_PACKET\]' > ./docs/logs/kernel-log-latest.txt

cd docs/logs

./save_log.sh kernel-log-latest.txt ratdma-sync 1node-50ms drone$1