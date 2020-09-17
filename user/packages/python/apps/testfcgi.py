#!/usr/bin/env python

from fcgi import WSGIServer

def myapp(environ, start_response):

    # parse the request into (user, page) pointers
    req = environ['REQUEST_URI']
    user, divider, page = req[1:].partition('/')
    print 'request ' + req + ' : ' + ' page ' + page + ' user ' + user

    # generate a standard reply
    start_response('200 OK', [('Content-Type', 'text/html')])
    return ['<html><body><h1>hello ' + user + '<h1><p> welcome to <i>your</i> page, ' + page + ' </p>\n</body></html>']

hostaddr = '0.0.0.0'
port = 8001

print 'Python FCGI test application\n  up at ' + str(hostaddr) + ':' + str(port)
WSGIServer(myapp, bindAddress = (hostaddr, port)).run() 
