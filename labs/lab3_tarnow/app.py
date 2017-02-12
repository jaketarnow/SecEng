#!/usr/bin/python
import sys
import dpkt
import urllib2
import re

def main():
	for arg in sys.argv[1:3]:
		if ".txt" in sys.argv[1]:
			text = sys.argv[1]
		if "http://" in sys.argv[2]:
			req_url = sys.argv[2]
	build_html(parse_pcap(text), req_url)

def parse_pcap(text):
	f = open(text)
	while True:
		reader = f.readline()
		if 'Cookie' in reader:
			cookie = re.findall(r'(?:\s+|$)[a-zA-Z].*', reader)
			return cookie
			break
	return null

def build_html(cookie, url):
	req = urllib2.Request(url)
	req.add_header("Cookie", cookie)
	resp = urllib2.urlopen(req)
	content = resp.read()
	print content

if __name__ == "__main__":
	main()