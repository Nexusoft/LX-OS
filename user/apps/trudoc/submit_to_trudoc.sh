#!/bin/bash

can=~/xml/canonicalize
#aas=~/pristine/user/apps/trudoc/aas_linux
aas=~/pristine/user/apps/trudoc/aas_nexus

outfile=/tmp/aas_docsigs.xml
tmpfile=/tmp/aas_docsigs.odt

if [ $# -le 1 ]; then
  echo "usage: aas target.odt src1.odt src2.odt ... srcN.odt" 1>&2
  exit 1
fi

expanded=""
for f in $*; do
  if [ ! -f $f ]; then
    echo "access error: $f" 1>&2
    exit 1
  fi
  n=`basename $f`
  g=/tmp/${n/.odt/}_odt
  echo "Preprocessing: $f"
  rm -rf $g
  mkdir $g
  unzip -q -d $g $f
  $can -q $g/{*.xml,META-INF/documentsignatures.xml}
  expanded="${expanded} $g"
  #(cd $g; zip -qr * /tmp/$n)
  #expanded="${expanded} /tmp/$n)
done

rm -rf $outfile
$aas $outfile $expanded
if [ ! -f $outfile ]; then
  echo "failed to attest" 1>&2
  exit 1
fi

t=$1
g=`basename $t`
g=/tmp/${g/.odt/}_odt
find $g -name '*.canonical.xml' | xargs rm -f

rm -rf $tmpfile
mv $outfile $g/META-INF/documentsignatures.xml
( cd $g; zip -qr $tmpfile * )
d=${t/.odt/}_attested.odt
mv $tmpfile $d

echo "Nexus attested to contents of $t, result is $d"

