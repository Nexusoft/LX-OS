#!/bin/bash

PYSERVER=file.py

echo "running latest fcgi.py?"
read

echo "disabling CPU frequency scaling"
sudo cpufreq_off
echo "disabling network-manager"
sudo /etc/init.d/network-manager stop
echo "disabling lighttpd"
sudo /etc/init.d/lighttpd stop

echo "mounting NFS"
if [[ ! -d usr/bin ]]
then
	sudo mount 10.0.0.1:/home/willem/src/nexus/build/boot usr/ || exit 1
fi
echo "populating /tmp"
sudo usr/linux/bin/nexirrus

echo "starting Python"
python usr/var/www/py/$PYSERVER &
sleep 1
echo "starting httpd.bin"
sudo usr/linux/bin/httpd

