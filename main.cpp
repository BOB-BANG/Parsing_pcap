#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#define ETHER_LEN 14
//ethernet_header DMAC 6byte, SMAC 6byte, Type 2byte
typedef struct sniff_mac
{
    u_char dmac[6];
    u_char smac[6];
    uint16_t type;
}mac_struct;

//IP header
typedef struct sniff_ip
{
    uint8_t ip_ver_and_ip_ihl;		// version 4bits, header length 4bit
    uint8_t ip_tos;		// type of service
    uint16_t ip_len;	//total length
    uint16_t ip_id;		//identification
    u_short ip_off;		//fragment offset field
#define IP_RF 0x8000	//reserved fragment flag
#define IP_DF 0x4000	//dont fragment flag
#define IP_MF 0x2000	//more fragments flag
#define IP_OFFMASK 0x1fff//mask for fragmenting bits
    u_char ip_ttl;		//time to live
    u_char ip_p;		//protocol
    u_short ip_sum;		//checksum
    uint32_t s_ip;		//source address
    uint32_t d_ip;		//dest address
} ip_struct;

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
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

void print_mac(u_char *mac)
{
   for(int i=0; i<6; i++){
       printf("%02X:",mac[i]);
       if(i!=5){
           printf("\n");
       }
   }
}
//    printf("%02X:%02X:%02X:%02X:%02X\n",mac->dmac[0]);
//}
//void printMac(u_int8_t *addr)
//{

  //int sizeOfMac=6;//mac address => 48bit
          //mac use hexadecimal number
          //Ex) AB:CD:EF:GH:YJ:KL
          //hexadecimal number use 4bit per 1 num
          //0 0 0 0 => 0
          //1 1 1 1 => F => 15

  /*for(int i=0; i<sizeOfMac;i++)
  {
      printf("%02X",mac[i]);
      if(i!=sizeOfMac-1)
          printf(":");
  }

}*/
void print_ip(uint8_t *ip){
    printf("%u.%u.%u.%u\n",ip[0],ip[1],ip[2],ip[3]);
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}


int main(int argc, char* argv[]) {
  //NO INPUT DEVICE
    if (argc != 2) {
    usage();
    return -1;
  }
  //ERROR FIND
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    mac_struct *mac;
    ip_struct* ip;



    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    mac = (mac_struct*)(packet);
    //printf("Packet Size : %u bytes\n", header->caplen);
    //printf("Destination MAC Address : ");
    print_mac(mac->dmac);

    //printf("Source MAC Address      : ");
    //printf("%02X:%02X:%02X:%02X:%02X:%02X\n", packet[7], packet[8], packet[9], packet[10], packet[11], packet[12]);
  }

  pcap_close(handle);
  return 0;
}
