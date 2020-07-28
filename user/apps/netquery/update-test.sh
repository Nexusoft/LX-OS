#!/bin/bash
sudo echo;
killall netqueryd
./netqueryd &
sleep 2
cd test
sudo opcontrol --start
sudo opcontrol --reset
../update-test $1 $2 $3
cd ..
killall -SIGINT netqueryd
sudo opcontrol --dump
opreport -l > results/opreport.${1}.${2}.${3}.out
gprof ./netqueryd gmon.out > results/netqueryd.${1}.${2}.${3}.out
gprof ./update-test test/gmon.out > results/update-test.${1}.${2}.${3}.out