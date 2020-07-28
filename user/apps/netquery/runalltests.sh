#!/bin/bash

ATTRIBUTES=1
TUPLES=100
TRANSACTIONS=1
OPS=100
SIZE=10

if [ $1 ] ; then
  ATTRIBUTES=$1
fi
if [ $2 ] ; then
  TUPLES=$2
fi
if [ $3 ] ; then
  TRANSACTIONS=$3
fi
if [ $4 ] ; then
  OPS=$4
fi
if [ $5 ] ; then
  SIZE=$5
fi

rm -f results.txt

for OPS in 100 500 1000 5000 10000 50000 100000 500000 1000000 5000000; do
  ATTRIBUTES=$OPS
  for j in 0 1 2; do
    for i in 0 1 2 3 4 5 6 7 8 9; do
      echo "Test $j$i :  $ATTRIBUTES $TUPLES $TRANSACTIONS $OPS $SIZE"
      export RESULT=`./runtest.sh $ATTRIBUTES $TUPLES $TRANSACTIONS $OPS $SIZE  2> /dev/null | grep "===> Total time" | sed 's/===> Total time: \([0-9]*\)[^0-9]*/\1/'`;
      echo "   $RESULT us"
      echo "$j$i $ATTRIBUTES $TUPLES $TRANSACTIONS $OPS $SIZE $RESULT" >> results.txt
    done
  done
done