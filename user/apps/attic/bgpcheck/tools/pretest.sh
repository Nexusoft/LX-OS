#!/bin/bash

#this is whatever directory you NFS mount in the nexus
export INSTALLDIR=/local/nexusdir
if [ $1 = "NLR-SHORT" ] ; then
  export SOURCEFILE="-t tools/inputs/nlr-short.src"
  export MYAS=19401
  export MYIP=216.24.191.226
elif [ $1 = "RV" ] ; then
  export SOURCEFILE="-d tools/inputs/rib.20080201.1545.bz2"
  export MYAS=6447
  export MYIP=128.223.51.102
else
  echo "You must specify a test to prepare for"
  exit
fi


export INSTALLFILES="grassroots.db sniffer.trace overlay.trace"

tools/loadprefixes.sh $SOURCEFILE $MYAS | tools/grassroots ^ > pretest.out

echo "Building trace files"
tools/bgpdump $SOURCEFILE -n $MYIP -a $MYAS -g pathlist.db -w sniffer.trace -x overlay.trace >> pretest.out
echo "... done"

echo "Exporting files to the Nexus"
cp $INSTALLFILES $INSTALLDIR
for i in $INSTALLFILES; do
  chmod 777 $INSTALLDIR/$i;
done
echo "... done"
