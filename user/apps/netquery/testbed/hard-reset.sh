#!/bin/bash

nodelist=node-list.txt

rm $nodelist
ssh root@ellen /root/resetvms

count=0
while (( count == 0 )) ; do
    count=$(wc -l node-list.txt)
    sleep 1
done

sleep 10

./gen-1path-topo.pl 7 > test.topo
./build-all-conf.pl test.topo
./remote-start.pl -S
