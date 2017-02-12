#!/usr/bin/python
import sys
import dpkt

def main():
	for arg in sys.argv[1:3]:
		if ".pcap" in sys.argv[1]:
			text = sys.argv[1]
		if "http://" in sys.argv[2]:
			req_url = sys.argv[2]
	print parse_pcap(text)

def parse_pcap(text):
	f = open(text)
	pcap = dpkt.pcap.Reader(f)

	for ts, buf in pcap:
		eth = dpkt.ethernet.Ethernet(buf)
		ip = eth.data
		tcp = ip.data

	if tcp.dport == 80 and len(tcp.data) > 0:
		http = dpkt.http.Request(tcp.data)
		print http.headers['user-agent']
	f.close()
	return http.headers['user-agent']

if __name__ == "__main__":
	main()