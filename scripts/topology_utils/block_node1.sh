#!/bin/bash

#Block broadcasts coming from Node 1
sudo ebtables -A INPUT -s d8:3a:dd:34:b7:cd -d FF:FF:FF:FF:FF:FF -j DROP

#Delete current rule
sudo ip neigh del 10.10.10.1 dev wlan0

#Add bogus permanent rule
sudo ip neigh add 10.10.10.1 lladdr 00:00:00:00:00:00 dev wlan0 nud permanent