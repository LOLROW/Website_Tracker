# Recieves requests made on device.

from scapy.all import *
from IPy import IP as ip_
import os
import datetime
import socket
import time
import numpy

def recieve(host):
	pktFlag = "$FLAGSTART"
	print("Now recieving messages from " + pktFlag)
	filter_ = "icmp and host " + host
	while True:
		try:
			pkt = sniff(filter=filter_, count = 2)
			message = pkt[0]
			message = str(message)
			indx = message.find(pktFlag[0])
			msg = message[indx:]
			msg = msg[:-1]
			print(msg)
		except:
			print("Something went wrong...")
recieve("192.168.1.242")