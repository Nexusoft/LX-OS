#/bin/bash

killall netqueryd

for CLIENT in $2; do
  ssh $CLIENT "killall update-test" 2> /dev/null
  scp *.principal $CLIENT:~/netquery_distro/
done

./netqueryd -s 1 &


i=0
while [ $i -lt $1 ] ; do
  let "port=i+5500"
  for CLIENT in $2; do
    echo "Spawning thread: " $i " on " $CLIENT ":" $port
    ssh $CLIENT "cd ~/netquery_distro/$CLIENT; ./update-test -h 128.84.227.47 -l -p $port" 2> /dev/null&
  done
  let "i+=1"
done

sleep 25

killall netqueryd
for CLIENT in $2; do
  ssh $CLIENT "killall update-test" 2> /dev/null
done
