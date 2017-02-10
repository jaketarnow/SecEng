#!/usr/bin/python

import sys

def main():
    # print command line arguments
    for arg in sys.argv[1:3]:
        if ".txt" in sys.argv[1]:
        	text = sys.argv[1]
        if "http://" in sys.argv[2]:
        	req_url = sys.argv[2]
    scrape_pcap(text)

def scrape_pcap(text):
	f = open(text)
	pcap = dpkt.pcap.Reader(f)

	for ts, buf in pcap:
		eth = dpkt.ethernet.Ethernet(buf)
	ip = eth.data
	tcp = ip.data

	if tcp.dport == 80 and len(tcp.data) > 0:
		http = dpkt.http.Request(tcp.data)
	print http.headers['user-agent']
	return http.headers['user-agent']

if __name__ == "__main__":
    main()