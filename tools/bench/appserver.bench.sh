#!/bin/bash

# 0 == httpd, 1 == file.py, 2 == size.py
#TEST= ... set below ...

# 0 == httperf, 1 == apache bench
BENCHMARK=1

BASENAME="/tmp/appbench"
SERVER=10.0.0.8
NUM=1001
RUNS=5

# single testrun
function dotest {
	echo "  run $BENCHNAME $TESTNAME count=$NUM concur=$CONCUR"
	echo "#Running $BENCHNAME $TESTNAME count=$NUM concur=$CONCUR" > $1
	for SIZE in `seq 60 1300 1360`
	#for SIZE in `seq 60 200 4260`
	do
		if [[ $BENCHMARK == 0 ]]
		then
			httperf --server $SERVER --num-conn $NUM --hog --uri /$PRE$SIZE$POST | grep Connection\ rate | awk "{print $SIZE \" \" \$3}" >> $1
		else
			ab -q -n $NUM -c $CONCUR http://$SERVER/$PRE$SIZE$POST | grep ^Request | awk "{print $SIZE \" \" \$4}" >> $1
		fi
		#echo "Press [enter] to continue"
		#read
	done
}

# set of runs and generate median
function dotest_med {
	if [[ $TEST == 0 ]]
	then
		TESTNAME="httpd"
		PRE="bench."
		POST=".html"
	elif [[ $TEST == 1 ]]
	then
		TESTNAME="file_py"
		PRE="pyfile/"
		POST=""
	elif [[ $TEST == 2 ]]
	then
		TESTNAME="size_py"
		PRE="pysize/"
		POST=""
	else
		print "No such test"
		exit 1
	fi

	if [[ $BENCHMARK == 0 ]]
	then
		BENCHNAME="httperf"
	else
		BENCHNAME="ab"
	fi

	echo "generating data"
	for RUN in `seq 1 1 $RUNS`
	do
		FILENAME=$BASENAME.$BENCHNAME.$TESTNAME.$CONCUR.$RUN
		dotest $FILENAME
	done
	echo "generating median"
	./median.py $BASENAME.$BENCHNAME.$TESTNAME.$CONCUR
}

# run httpd 
CONCUR=10
TEST=0
dotest_med

CONCUR=5
TEST=1		# run file.py
#TEST=2		# run size.py

dotest_med


