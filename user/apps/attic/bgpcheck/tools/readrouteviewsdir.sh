#!/bin/bash

for i in $1/updates.*.bz2; do
	j=`basename $i .bz2`
	echo ------ $j ------
	cp $i .
	rm -f $j
	bzip2 -d $j.bz2
	./bgpdump -d $j -u 2> /dev/null | grep -v "Found IP"
	for k in updates/*.src; do 
		echo "SEGMENT_DONE: $j" >> $k
	done
done