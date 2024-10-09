# Script to start a dhcp server on the controlling computer. This dhcp server will allow wired connections to the RPIs for testing.

sudo ifconfig eno1 255.255.255.0 192.168.10.10
sudo service isc-dhcp-server restart
sudo service isc-dhcp-server status