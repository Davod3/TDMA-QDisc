#!/bin/bash

gcc -I. -I./include -c -o ./tc_tdma.o ./tc_tdma.c;
gcc -I./include -c -o ./lib/librtnetlink.o ./lib/librtnetlink.c;

ar rcs ./lib/librtnetlink.a ./lib/librtnetlink.o;
gcc -o ./tc_tdma ./tc_tdma.o ./lib/librtnetlink.a;
