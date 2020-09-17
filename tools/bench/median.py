#!/usr/bin/env python
#
# parse a set of files <basepath>.<id> that contain 
# two space separates lists, for x y coordinates in gnuplot
#
# calculate the median, upper and lower quantile of measurements

import sys

count = 5			# number of measurements
echo "[median] runs=$count"

def readfiles(basepath):
	data = {}
	for i in range(1, count + 1):
		file = open(basepath + '.' + str(i))
		for line in file:
			if line[0] != '#':
				x, y = line.split(' ')
				x = int(x)
				if not x in data:
					data[x] = []
				data[x].append(float(y))
	file.close()
	return data

def calc_median(data, outfile):
	outfile.write('#key \tQ2 \tQ1 \tQ3 \tQ1% \tQ2%\n')
	for key, values in sorted(data.iteritems()):
		values.sort()
		q1diff = values[q2] - values[q1]
		q3diff = values[q3] - values[q2]
		q1reldiff = (q1diff * 100.0) / values[q2]
		q3reldiff = (q3diff * 100.0) / values[q2]
		outfile.write(str(key) + '\t' + str(values[q2]) + '\t' + str(values[q1]) + '\t' + str(values[q3]) + '\t' + str(q1reldiff) + '\t' + str(q3reldiff) + '\n')


# parse input
if len(sys.argv) != 2:
	print 'Usage: ' + sys.argv[0] + ' <basepath>'
	print '        where basepath is the filepath of measurements minus .<number>'
	exit(1)

if (count / 2) * 2 == count:
	print 'Count must be odd'
q2 = count / 2
q1 = q2 / 2
q3 = q2 + q1

data = readfiles(sys.argv[1])
outfile = open(sys.argv[1] + '.med', 'w')
calc_median(data, outfile)
outfile.close()

