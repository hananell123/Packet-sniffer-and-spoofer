#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

// Our ICMP Header
struct icmpheader {
	unsigned char icmp_type;
	unsigned char icmp_code;
	unsigned short int icmp_chksum;
	unsigned short int icmp_id;
	unsigned short int icmp_seq;
};
// Our IP Header
struct ipheader {
	unsigned char iph_ihl:4, iph_ver:4;
	unsigned char iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_flag:3, iph_offset:13;
	unsigned char iph_ttl;
	unsigned char iph_protocol;
	unsigned short int iph_chksum;
	struct in_addr iph_sourceip;
	struct in_addr iph_destip;
};
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};

void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, 
                     &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0, 
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}
unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all 
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
   sum += (sum >> 16);                  // add carry 
   return (unsigned short)(~sum);
}
int main() {
	char buffer[1500];
	memset(buffer, 0, 1500);
	
	char data[IP_MAXPACKET]="this is a ping";
	char packet[IP_MAXPACKET];
	int data_len = strlen(data)+1;

	struct ipheader *ip = (struct ipheader *) packet;
	struct icmpheader *icmp = (struct icmpheader *) (packet + sizeof(struct ipheader));

	
	// Filling in the ICMP header
	memcpy(packet+sizeof(struct ipheader)+sizeof(struct icmpheader),data,data_len);
	icmp->icmp_type=8;
	icmp->icmp_chksum=0;
	icmp->icmp_id =4;
	icmp->icmp_seq=6;
	icmp->icmp_chksum = in_cksum((unsigned short *)(packet+20), 
                                 sizeof(struct icmpheader)+data_len);

	// Filling in the IP header
	ip->iph_ver = 4;
	ip->iph_ihl = 5;
	ip->iph_ttl = 20;
	ip->iph_chksum=0;
	ip->iph_sourceip.s_addr = inet_addr("10.9.0.5");
	ip->iph_destip.s_addr = inet_addr("8.8.8.8");
	ip->iph_protocol = IPPROTO_ICMP;
	ip->iph_len=htons(sizeof(struct ipheader)+sizeof(struct icmpheader)+data_len);

	
	
	// Here we send the spoofed packet
	send_raw_ip_packet(ip);
	return 0;
}
