#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN	6 /* Ethernet addresses are 6 bytes */

struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};

struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

typedef u_int tcp_seq;

	struct tcpheader {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;	/* sequence number */
		tcp_seq th_ack;	/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, 
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;
  struct ipheader *iphdr = (struct ipheader *)(packet + sizeof(struct ethheader));
  struct tcpheader *tcphdr = (struct tcpheader *)(packet + sizeof(struct ipheader) + sizeof(struct ethheader));
  char *telnet = (char *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcpheader));
  int telnet_size = ntohs(iphdr->iph_len) - sizeof(struct ipheader) - sizeof(struct tcpheader);
  for (int i = 0; i < telnet_size; i++)
  {
    printf("%c",telnet[i]);
  }
  printf("\n");
  printf("finished one packet\n");

}
int main()
{
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "tcp port 23";
bpf_u_int32 net;
// Step 1: Open live pcap session on NIC with name br-1ca35f87b2fa
// Students needs to change "eth3" to the name
// found on their own machines (using ifconfig).
handle = pcap_open_live("br-e4b879658211", BUFSIZ, 1, 1000, errbuf);
// Step 2: Compile filter_exp into BPF psuedo-code
pcap_compile(handle, &fp, filter_exp, 0, net);
pcap_setfilter(handle, &fp);
// Step 3: Capture packets
pcap_loop(handle, -1, got_packet, NULL);
pcap_close(handle); //Close the handle
return 0;
}
