echo 'Inserting sch_netem kernel module...'
sudo modprobe sch_netem

echo 'Adding QDisc kernel modules...'
cd ..
make
make install

echo 'Adding TDMA Qdisc...'
sudo ./netcntlr/manage_qdisc

echo 'Qdisc added...'
echo '-------------------'
lsmod | grep sch_netem
echo '-------------------'
lsmod | grep tdma
echo '-------------------'
lsmod | grep netlink_sock
echo '-------------------'