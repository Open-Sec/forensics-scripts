#!/usr/bin/python

import re,urllib2
import sys
import time

count = 0

if len(sys.argv) != 2:
    print "Usage: ./check-urls-virustotal.py <File-URLs>"
    sys.exit(1)

print "Checking in virustotal.com\n"
print "======================================="

with open('url.lst') as f:
   for url in f:
	try:
		time.sleep(1)
		url_requested = 'https://www.virustotal.com/en/url/submission/?force=1&url='+url

		response = urllib2.urlopen(url_requested)
		payload = response.read()

		regex = re.compile('0/5')
		results_q1 = regex.findall(payload)

		count += 1

		if len(results_q1) == 0:
			print "url "+str(count)+": "+url+"already reported....................!!!!"
			print " "
		else:
			print "url "+str(count)+": "+url+"Detection ratio : 0"
			print " "

	except IOError, e:
	    if hasattr(e, 'code'): # HTTPError
	        print 'http error code: ', e.code
	    elif hasattr(e, 'reason'): # URLError
	        print "can't connect, reason: ", e.reason
	    else:
       		raise

	if 'str' in url:
		break
