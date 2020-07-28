#!/bin/bash

while true ; do
    killall -USR2 netqueryd microbench > /dev/null 2>/dev/null
    sleep 1
done
