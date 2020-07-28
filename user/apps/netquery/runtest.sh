#/bin/bash


ssh orlando "killall netqueryd" 2> /dev/null
ssh orlando "cd /loki/user/apps/netquery/; ./netqueryd" 2> /dev/null > /dev/null &
sleep 1
./update-test $*
ssh orlando "killall netqueryd" 2> /dev/null