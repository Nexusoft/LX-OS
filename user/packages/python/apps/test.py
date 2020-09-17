#!/usr/bin/env python

# file must exist
filepath = '/bin/version'
#filepath = '/etc/fstab'

print "python selftest"

import sys
print "arguments: " + str(len(sys.argv))

import __builtin__
print 'built-in modules: ' + str(len(dir(__builtin__)))

import platform
print 'platform: ' + platform.platform()

import os
print 'environment: ' + str(len(os.environ))
os.environ['hello'] = 'world'
envval = os.getenv('hello')
if envval != 'world':
	print 'envtest FAILED'
	exit(1)

# date
import datetime
print 'date: ' + str(datetime.date.today())

## file I/O
file = open(filepath, "r")
text = file.readline()
print 'file contents: ' + text
file.close()

## socket I/O 
# XXX expand with real networking
import socket

print 'socket test'
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('', 1123))	
sock.close()
print 'socket test completed'

## md5
import hashlib

md = hashlib.md5()
md.update("firsttry")
print 'md5: ' + md.hexdigest()

### threads
import threading

class workerthread(threading.Thread):

	def __init__(self, string):
		self.string = string
		threading.Thread.__init__(self)

	def run(self):
		print self.string

print 'starting background worker'
worker = workerthread("background thread active")
worker.start()
worker.join()
print 'joined background worker'

### add http clientside communication
import httplib

print 'connecting to Cornell webserver'
print 'warning: this may fail simply because the IP address is down'
hclient = httplib.HTTPConnection("128.84.97.36");
#hclient = httplib.HTTPConnection("128.84.154.137");
print 'requesting Nexus page'
hclient.request("GET", "/People/egs/nexus/");
print 'waiting for reply'
hreply = hclient.getresponse()
print 'reply: ' + str(hreply.status) + ' ' + str(hreply.reason)
print hreply.read()
hclient.close()

### CGI (setup only)
import cgitb
import cgi

print 'cgi test'
cgitb.enable()
cgi.test()
cgi.print_environ()
print 'cgi test completed'

### sqlite
import sqlite3

try:
	conn = sqlite3.connect(':memory:')
	c = conn.cursor()
	c.execute('create table keyval (key text, value text)')
	c.execute('insert into keyval values ("one", "uno")')
	c.execute('insert into keyval values ("two", "due")')
	conn.commit()
	c.execute('select * from keyval where key="one"')
	for row in c:
		print 'OK: retrieved row from database'
	c.close()
	conn.close()
except:
	print 'sqlite failed'

## ssl

try:
	import ssl
except ImportError:
	print 'ssl failed'     
else:
	print 'ssl entropy is ' + str(ssl.RAND_status())

## email
from email.mime.text import MIMEText

try:
	print 'imported email'
	msg = MIMEText('an email from Nexus')
	print 'created email message'

	msg['Subject'] = "the nexus license file"
	msg['From'] = "user@localhost"
	msg['To'] = "recipient@otherhost"

	print 'email: ' + str(msg) + 'B'
except:
	print 'email failed'

### XXX add FastCGI (requires download fcgi module)


print 'OK. selftest passed'

