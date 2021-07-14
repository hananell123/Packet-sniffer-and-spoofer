from scapy.all import *

def show_pkt(pkt) :
	pkt.show()

pkt=sniff(iface=['br-ef6bf2313a33','enp0s3','lo'], filter='tcp and dst port 23 and src host 10.0.2.15', prn=show_pkt)
