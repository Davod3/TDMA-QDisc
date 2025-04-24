#!/bin/bash

#Block broadcasts coming from Node 1
#sudo tc qdisc add dev wlan0 clsact
#sudo tc filter add dev wlan0 ingress protocol all flower src_mac d8:3a:dd:96:6e:12 dst_mac ff:ff:ff:ff:ff:ff action drop
sudo iptables -t raw -I PREROUTING -s 10.10.10.6 -m addrtype --dst-type BROADCAST -j DROP

#Delete current rule
sudo ip neigh del 10.10.10.6 dev wlan0

#Add bogus permanent rule
sudo ip neigh add 10.10.10.6 lladdr 00:00:00:00:00:00 dev wlan0 nud permanent