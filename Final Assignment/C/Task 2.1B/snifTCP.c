#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN	6

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

void got_packet(u_char *args, const struct pcap_pkthdr *header, 
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 


    /* determine protocol */
    switch(ip->iph_protocol) {                               
        case IPPROTO_TCP:
            printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));  
            printf("         To: %s\n", inet_ntoa(ip->iph_destip));   
            printf("   Protocol: TCP\n");
            return;

 default:
            printf("   Protocol: others\n");
            return;
    }
  }
}
int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
 char filter_exp[] = "tcp and dst portrange 10-100";
bpf_u_int32 net;

  //*Step 1: Open live pcap session on NIC with name br-1ca35f87b2fa.
  handle = pcap_open_live("br-1ca35f87b2fa", BUFSIZ, 1, 1000, errbuf); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);                             

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}
