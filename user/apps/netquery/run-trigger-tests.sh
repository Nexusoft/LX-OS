#!/bin/bash

MYIP=128.84.227.11
NETQUERYD="./netqueryd -g"
. ipsetup # should override settings above

HOST="-h $MYIP"

function finished() {
	echo "========="
	echo "Success count: $success_count"
	echo "========="
	exit $1
}
function reset() {
	killall netqueryd
	killall trigger-test
	sleep 2
}

function banner() {
    echo "===================================";
    echo "===== Testing $1";
    echo "===================================";
}

function single_client() {
	abort=$1 # 2 = commit, 3 = abort
	count=$2
	match_count=$3
	extra_args=$4
	banner "Single client $*"

	reset
	$NETQUERYD &
	sleep 2
	./trigger-test $HOST 0
	sleep 1
	( sleep 2 ; ./trigger-test $HOST $abort ) &
	cmdline="./trigger-test -k $count --veto $match_count --sync $match_count --done $match_count --async 0 $extra_args $HOST 1"
	echo $cmdline
	$cmdline
}

function single_client_extra() {
# Verify that other attributes with the same name don't match
	abort=$1 # 2 = commit, 3 = abort
	count=$2
	match_count=$3
	extra_args=$4
	banner "Single client extra $*"

	reset
	$NETQUERYD &
	sleep 2
	./trigger-test $HOST 0

	(
		sleep 5 # run after the write below
		./trigger-test $HOST 0
		./trigger-test $HOST 0
		./trigger-test $HOST 0
		./trigger-test $HOST 0
	) &
	sleep 1
	# run write before the original tid file is overwritten
	( sleep 3 ; ./trigger-test $HOST $abort ) &
	cmdline="./trigger-test -k $count --veto $match_count --sync $match_count --done $match_count --async 0 $extra_args $HOST 1"
	echo $cmdline
	$cmdline
}

h0="-h $MYIP -p 7000"
h1="-h $MYIP -p 7001"
h2="-h $MYIP -p 7002"

function start_multi() {
	reset
	$NETQUERYD &
	$NETQUERYD -p 7000 &
	$NETQUERYD -p 7001 &
	$NETQUERYD -p 7002 &
	sleep 2

	./trigger-test $h0 0
	./trigger-test $h1 0
	./trigger-test $h2 0
}


function multi_server() {
	abort1=$1 # 2 = commit, 3 = abort
	abort_other=$2
	match_count=$3
	#count=$2
	#match_count=$3
	#match_count=7

	start_multi

	extra_args="$4"
	banner "Multi server $*"

	cmdline="./trigger-test -k 1 --veto $match_count --sync $match_count --async 0 --done $match_count $extra_args $HOST 4"
	echo $cmdline

	(
		sleep 3
		./trigger-test -k 1 $h0 $abort1
		./trigger-test -k 2 $h1 $abort_other
		./trigger-test -k 4 $h2 $abort_other
	) &

	$cmdline
}


function multi_commit() {
	abort=$1
	match_count=$2
	extra_args="$3"

	start_multi

	cmdline="./trigger-test -k 1 --veto $match_count --sync $match_count --async 0 $extra_args --done $match_count $HOST 4"
	echo $cmdline

	(
		sleep 3
		./trigger-test -k 1 $h0 $abort
	) &

	$cmdline
}

if true ; then

	if  ! single_client_extra 2 1 1 ; then
		echo single_client_extra 1 failed
		finished -1
	else
		(( success_count ++ ))
	fi

	if  ! single_client 2 1 1 ; then
		echo single_client 1 failed
		finished -1
	else
		(( success_count ++ ))
	fi

	if  ! single_client 2 5 5 ; then
		echo single_client 5 failed
		finished -1
	else
		(( success_count ++ ))
	fi

	if  ! single_client 3 5 0 ; then
		echo single_client abort failed
		finished -1
	else
		(( success_count ++ ))
	fi

	if  ! single_client 2 5 5 "--vetoone --expectfail" ; then
		echo single_client veto one expect fail failed
		finished -1
	else
		(( success_count ++ ))
	fi

if false ; then
    echo "foo"
fi # if false

if ! multi_server 2 2 7 ; then
	echo "multi server, committed, single write/transaction failed"
	finished -1
else
	(( success_count ++ ))
fi

fi

if ! multi_server 5 5 3 ; then
	echo "multi server, committed, multiple writes/transaction failed"
	finished -1
else
	(( success_count ++ ))
fi

if true ; then


if ! multi_commit 6 3 ; then
	echo "one commit, multiple servers, commit failed"
	finished -1
else
	(( success_count ++ ))
fi

if ! multi_commit 7 0 ; then
	echo "one commit, multiple servers, abort failed"
	finished -1
else
	(( success_count ++ ))
fi

if ! multi_commit 6 3 "--vetoone --expectfail" ; then
	echo "one commit, multiple servers, veto failed"
	finished -1
else
	(( success_count ++ ))
fi

fi # if false


finished 0

