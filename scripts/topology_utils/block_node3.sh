#!/bin/bash

#Block broadcasts coming from Node 1
sudo ebtables -A INPUT -s d8:3a:dd:e0:9c:d4 -d FF:FF:FF:FF:FF:FF -j DROP

#Delete current rule
sudo ip neigh del 10.10.10.3 dev wlan0

#Add bogus permanent rule
sudo ip neigh add 10.10.10.3 lladdr 00:00:00:00:00:00 dev wlan0 nud permanent