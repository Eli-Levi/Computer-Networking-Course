#include <sys/socket.h>
#include <linux/if_packet.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h> 

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};
/* IP Header */
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
/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};

/*************************************************************
  Given an IP packet, send it out using a raw socket. 
**************************************************************/
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

void spoof(struct ipheader * ip)
{
    const char buffer[1500];
    int ip_header_len = ip->iph_ihl * 4;

    //* Make a copy from the original packet .
    memset((char*)buffer, 0, 1500);
    memcpy((char*)buffer, ip, ntohs(ip->iph_len));
    struct ipheader  * newip  = (struct ipheader *) buffer;
    struct icmpheader* newicmp = (struct icmpheader*)(buffer + ip_header_len);

    //* Swap the src and dst in the new ICMP packet.
    newip->iph_sourceip = ip->iph_destip;
    newip->iph_destip = ip->iph_sourceip;
    newip->iph_ttl = 64; //*Linux kernel 4.10 (2015): 64 for TCP, UDP and ICMP .

    //* Make the ICMP packet look like a reply (Type: 0).
    newicmp->icmp_type = 0;
   
    //* Send out the spoofed IP packet .
    send_raw_ip_packet(newip);
}




void got_packet(u_char *args, const struct pcap_pkthdr *header, 
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));  
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));   

    /* determine protocol */
    switch(ip->iph_protocol) {                               
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            spoof(ip);
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
  char filter_exp[] = "ICMP from some src and dest IP 10.9.0.5 .";
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
