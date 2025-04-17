#!/bin/bash

sudo ebtables -D INPUT -s d8:3a:dd:e0:9f:f3 -d FF:FF:FF:FF:FF:FF -j DROP

#Delete current rule
sudo ip neigh del 10.10.10.4 dev wlan0