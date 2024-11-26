#!/bin/bash

sudo service NetworkManager stop
sudo ifconfig $1 down
sudo iwconfig $1 mode monitor
sudo ifconfig $1 up
sudo iwconfig $1 channel 40
sudo iwconfig $1 channel 1
iwconfig
