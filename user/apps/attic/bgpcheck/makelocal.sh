#!/bin/bash

# Testing takes place on several different computers all connected via NIS/NFS
# In other words, they're all running out of the same directory.  For some reason
# (variances in architecture or linux version maybe?) binaries produced on some
# of machines aren't compatible with binaries produced on others. 
# This script makes a copy of each of its parameters subscripted with the local
# hostname (ie `makelocal.sh foo` === `cp foo foo.myhost`) so that compiles on
# multiple machines don't clobber each other.
# - Oliver

for i in $*; do
    cp $i $i.`hostname | sed 's/\([^\.]*\)\..*/\1/'`; 
done;
