#!/bin/bash

## Configuration

# boolean. MUST correspond with server configuration
ENCRYPT=0

# repeat test for median calculation
NUM_RUNS=11

# base filename, minus config and run-specific scheme
BASEPATH="/tmp/spawn.data"

## Variables

EXECUTABLE=./build/linux/bin/spawn
MEDIANTOOL=./tools/bench/median.py
PORT=10000

if [[ $ENCRYPT == 1 ]]
then
	ENCNAME="crypto"
else
	ENCNAME="plain"
fi

## Code

# call single setting for multiple #read commands
function do_all_sizes() {
	for SIZE in `seq 0 25 200`
	do
		echo "  session length $SIZE"
		$EXECUTABLE -c $PORT $ENCRYPT $SIZE >> $FILEPATH
		let PORT+=1
	done
}

function do_repeat() {
	for i in `seq 1 1 $NUM_RUNS`
	do
		echo "run $i"
		FILEPATH="$BASEPATH.$ENCNAME.$i"
		echo "# spawn $ENCNAME " > $FILEPATH
		do_all_sizes
	done
}

# generate data
do_repeat

# generate median and friends
$MEDIANTOOL $BASEPATH.$ENCNAME > "$BASEPATH.$ENCNAME.med"
cat "$BASEPATH.$ENCNAME.med"


