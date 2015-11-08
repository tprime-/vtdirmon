#!/usr/bin/env python
#
# Monitors a directory for added files, uploads them to VirusTotal, and returns the results
#

import pyinotify
import virustotal
from hashlib import md5
import sys

# instantiate the virustotal handler. include our API key here
v = virustotal.VirusTotal('API key here')
 
# Watch Manager
wm = pyinotify.WatchManager()
# watched events - delete, write close, moved into directory
mask = pyinotify.IN_DELETE | pyinotify.IN_CLOSE_WRITE | pyinotify.IN_MOVED_TO

# function to check the md5sum client-side
def md5sum(filename):
	hash = md5()
	with open(filename, "rb") as f:
		for chunk in iter(lambda: f.read(128 * hash.block_size), b""):
			hash.update(chunk)
	return hash.hexdigest()
	
# start a virustotal scan
def process_file(file):
	print '[*] File detected:', file
	print '[*] Original MD5:', md5sum(file)
	print '[*] Uploading file to VirusTotal\n'
	try:
		report = v.scan(file)
	except:
		print '[!] Error contacting VirusTotal'
		sys.exit(1)
		
	# Wait for the report to be ready
	print '[*] Waiting for the scan to complete'
	report.join()
	assert report.done == True
	
	if report.done:
		# Read the report
		print '[*] VirusTotal results:'
		print '[*] Scan UID:', report.scan_id
		print '[*] VT MD5:', report.md5
		#check for md5 checksum match
		if md5sum(file) == report.md5:
			print '[*] MD5 checksums match'
		else:
			print '[!] MD5 checksum mismatch'
		print '[*] Report link:', report.permalink
		print '[*] Positives:', report.positives
		# check for any virus engines detecting malware
		if report.positives == 0:
			print '[*] Status: Clean'
		else:
			print '[!] Status: Infected'
		print ''

# get our directory to monitor from stdin
if len(sys.argv) == 2:
	target_dir = sys.argv[1]

	class EventHandler(pyinotify.ProcessEvent):
		def process_IN_CLOSE_WRITE(self, event):
			file = event.pathname
			process_file(file)
		
		def process_IN_MOVED_TO(self, event):
			file = event.pathname
			process_file(file)
				
		def process_IN_DELETE(self, event):
			print "[*] File removed:", event.pathname

	handler = EventHandler()
	notifier = pyinotify.Notifier(wm, handler)
	wdd = wm.add_watch(target_dir, mask, rec=True)

	notifier.loop()

else:
	print 'Usage: ./vtdirmon.py <directory>\n'
