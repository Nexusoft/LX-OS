#!/usr/bin/env python

import sys
import inspect
import hashlib

# cache the short-form name for the current environment
# NB: name can get outdated: when an extra module is imported
#     .._modcount helps guard by keeping track of #modules
__internal_name = None
__internal_modcount = 0

def hashfile(filepath):
    fd = open(filepath)
    data = fd.read()
    fd.close()
    return hashlib.sha1(data);

def hashfiles():
    '''Create a system fingerprint by hashing all modules'''
    sources = {}

    # add module hashes (main script is __main__)
    for key, value in sys.modules.items():
        try:
            source = inspect.getfile(value)
            sources[key] = hashfile(source)
        except TypeError:
            # builtin: no need to hash: part of python binary hash
            pass
    return sources

def hashprint():
    '''Create a system fingerprint. 
       'activecode' hashes the hashes to create a short unique name'''

    hashtable = hashfiles()

    # turn dictionary into a string of name=hash pairs
    prettylist = []
    keys = hashtable.keys()
    keys.sort()
    for key in keys:
        prettylist.append("%s=%s" % (key, hashtable[key].hexdigest()))
    prettystring = ' and '.join(prettylist)

    # prepend activecode element
    __internal_name = hashlib.sha1(prettystring).hexdigest()
    return 'activecode=%s %s' % (__internal_name, prettystring)

def name():
    '''Return the short form name'''
    if __internal_name == None:
        hashprint()
    print 'fuck, why doesn\'t this function work correctly?'
    return __internal_name

if __name__ == "__main__":
    print hashprint()

