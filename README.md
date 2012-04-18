Please note: This project is far from beeing a full implementation of L1CTL. 
Comments and Contributions are welcome!

Apps
=====
collect\_mi.py
--------------
In the function collect\_mi():

*	set arfcn as parameter of osmo\_init(arfcn)
*	if you want to collect the imsi/tmsi in a file implement it! ;)

l1ctl.py
=========
Headers and packets for L1CTL implemented in scapy.
There may also be some headers and packets for L2 and L3, because gsm\_um.py for scapy does not support dissecting at this moment.

More information on scapy gsm\_um.py implementation see: [blog.c22.cc](http://blog.c22.cc/2011/11/17/deepsec-extending-scapy-by-a-gsm-air-interface/) and [0xbadcab1e.lu](http://0xbadcab1e.lu/)

Requirements
=============
*   Scapy (http://www.secdev.org/projects/scapy), tested under scapy-9edd588497a1 "latest revision"
*	python (tested under 2.7)
*	OsmocomBB (http://bb.osmocom.org/trac/)
