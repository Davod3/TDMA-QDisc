#!/bin/bash

#sudo tc qdisc del dev wlan0 clsact
#sudo tc filter del dev wlan0 ingress
sudo iptables -t raw -D PREROUTING -s 10.10.10.3 -m addrtype --dst-type BROADCAST -j DROP

#Delete current rule
sudo ip neigh del 10.10.10.3 dev wlan0