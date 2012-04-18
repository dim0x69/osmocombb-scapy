#!/usr/bin/python2.7

from l1ctl import *
import socket
from scapy.all import *
import SocketServer

osmosock = None

def osmo_read():
	print "read()"
	global osmosock
	buff = osmosock.recv(100)
			
def init_osmosock():
	global osmosock
	osmosock  = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
	osmosock.connect('/tmp/osmocom_l2')

def osmo_send(msg):
	msg = str(msg)
	global osmosock
	osmosock.send(msg)


def collect_mi():
	init_osmosock()
	osmo_init(1005)
	global osmosock
	while True:
		buff = osmosock.recv(100)
		p = l1ctl_hdr(buff)
		try:
			mi = p.payload.payload.payload.getfieldval("mi")
			miLen = len(mi)
			if miLen is 8 or miLen is 5:
				hexdump(mi)
			try: 
				mi2 = p.payload.payload.payload.getfieldval("mi2")
				mi2Len = len(mi2)
				if mi2Len is 8 or mi2Len is 5:
					hexdump(mi2)
			except:
				pass
		except:
			pass
		
def osmo_init(arfcn):
	l1_hdr = l1ctl_hdr(msg_type=L1CTL_RESET_REQ)
	l1_res = l1ctl_reset()
	osmo_send(l1_hdr / l1_res)
	osmo_read()
	l1_hdr = l1ctl_hdr(msg_type=L1CTL_FBSB_REQ)
	l1_fbsb = l1ctl_fbsb_req(band_arfcn=arfcn)
	osmo_send(l1_hdr / l1_fbsb)
	osmo_read()

collect_mi()
