#!/usr/bin/python

import re,urllib2, httplib
import sys
import time

if len(sys.argv) != 3:
    print "Usage: ./checkdlls-google.py <File-DDLs> <NumMatch>"
    sys.exit(1)

datafile=sys.argv[1]
nummatch=sys.argv[2]

print "Checking in google.com\n"
print "======================================="

with open(datafile) as f:
   for item_name in f:
	try:
		time.sleep(1)
		headers = { 'User-Agent' : 'Mozilla/5.0' }
		url = 'http://www.google.com/search?q='+item_name
		print "checking.........:"+item_name
		requesthttp = urllib2.Request(url,None, headers)
		responsehttp = urllib2.urlopen(requesthttp)
		payload = responsehttp.read()
		regex = re.compile('malware', re.IGNORECASE)
		results_q1 = regex.findall(payload)

		if len(results_q1) > int(nummatch):
			print "This DLL already reported ["+str(len(results_q1))+"]....................!!!!"

	except IOError, e:
	    if hasattr(e, 'code'): # HTTPError
	        print 'http error code: ', e.code
	    elif hasattr(e, 'reason'): # URLError
	        print "can't connect, reason: ", e.reason
	    else:
       		raise

	if 'str' in url:
		break
