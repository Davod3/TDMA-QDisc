#!/bin/bash

sudo ebtables -D INPUT -s d8:3a:dd:e0:9c:d4 -d FF:FF:FF:FF:FF:FF -j DROP

#Delete current rule
sudo ip neigh del 10.10.10.3 dev wlan0