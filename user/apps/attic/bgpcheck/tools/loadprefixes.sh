#!/bin/bash
tools/bgpdump $1 $2 -l $3 | grep ^map: | sed 's/map: //' | awk '{print $2,$1;}'
# | sort -n
