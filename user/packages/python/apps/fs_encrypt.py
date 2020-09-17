#!/usr/bin/env python
#
# run a lockbox on the primary lockboxport (which should be 4141)

import os
import time
import nexus
import fcntl

lockboxport = 4121

# start lockbox
#print 'starting lockbox on port ' + str(lockboxport)
#nexus.run("/bin/lockbox.app p f")
#time.sleep(2)
print 'make sure that the primary LOCKBOX is UP at ipc port ' + str(lockboxport)

# read plaintext
file = open('/bin/LICENSE')
data = file.read()
file.close()

# create ciphertext
cryptfile = open('/tmp/LICENSE.crypt', 'w')
if fcntl.fcntl(cryptfile, 0x2000, lockboxport << 16):
	print 'fcntl failed'
cryptfile.write(data)
cryptfile.close()

#print 'created ciphertext'
#raw_input('press [enter] to decrypt')

# decrypt ciphertext
cryptfile = open('/tmp/LICENSE.crypt', 'r')
if fcntl.fcntl(cryptfile, 0x2000, lockboxport << 16):
	print 'fcntl failed'
data = cryptfile.read()
cryptfile.close()

print data
print 'did that look right? (%dB)' % (len(data)) 
raw_input('press [enter] to show ciphertext')

# reread, now without encryption
cryptfile = open('/tmp/LICENSE.crypt', 'r')
data2 = cryptfile.read()
cryptfile.close()
print data2
print 'how about that? (%dB)' % (len(data2)) 

# verify length
if (len(data) != len(data2)):
	print 'Error: lengths differ. Abort'
	exit()

# compare. each character should be offset by 128B if using lockbox.test
dlen = len(data2)
for i in range(dlen):
	c1 = ord(data[i]) 
	c2 = ord(data2[i]) + 128
	if (c1 % 256 != c2 % 256):
		print 'characters differ at ' + str(i) + ' ' + int(data[i]) + ' ' + int(data2[i])

# cleanup
os.unlink('/tmp/LICENSE.crypt')
print '[OK]'

