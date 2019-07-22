#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#define ETHER_LEN 14
#define IP_LEN (((ip)->ip_ver_and_ip_ihl)&0x0F)*4
#define TCP_LEN ((((tcp)->th_offx2 & 0xf0) >> 4))*4

//ETHERNET HEADER DMAC 6byte, SMAC 6byte, Type 2byte
typedef struct sniff_mac
{
    u_char dmac[6];
    u_char smac[6];
    uint16_t type;
}mac_struct;

//IP HEADER
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
    u_char sip[4];		//source address
    u_char dip[4];		//dest address
} ip_struct;

//#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
//#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;
//TCP HEADER
typedef struct sniff_tcp {
    u_short sport;	    //source port
    u_short dport;	    //destination port
    tcp_seq th_seq;		//sequence number
    tcp_seq th_ack;		//acknowledgement number
    u_char th_offx2;	//data offset, rsvd
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
    u_short th_win;		// window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
} tcp_struct;

void print_mac(u_char *mac){
   for(int i=0; i<6; i++){
       printf("%02X",mac[i]);
       if(i==5){
           printf("\n");
       }
       else {
           printf(":");
       }
   }
}

void print_ip(u_char *ip){
    for(int i=0; i<4; i++){
        printf("%02d",ip[i]);
        if(i==3){
            printf("\n");
        }
        else {
            printf(".");
        }
    }
}

void print_port(u_short port){
    printf("%02d",ntohs(port));
    printf("\n");
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
    mac_struct* mac;
    ip_struct* ip;
    tcp_struct* tcp;
    const u_char* payload;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //printf("\n\nPacket Size             : %u bytes\n", header->caplen);


    //PRINT MAC
    printf("\n\n===========MAC print============\n");
    mac = (mac_struct*)(packet);
    printf("Destination MAC Address : ");
    print_mac(mac->dmac);
    printf("Source MAC Address      : ");
    print_mac(mac->smac);
    printf("%d",mac->type);

    if(mac->type == ntohs(0x0800)){
      //PRINT IP
      printf("===========IP print=============\n");
      ip = (ip_struct*)(packet+ETHER_LEN);
      printf("Destination IP Address  : ");
      print_ip(ip->dip);
      printf("Source IP Address       : ");
      print_ip(ip->sip);
      //printf("ip header Size          : %d bytes\n",IP_LEN);

      if(ip->ip_p == 6){
        //PRINT TCP
        printf("===========PORT print============\n");
        tcp = (tcp_struct*)(packet+ETHER_LEN+IP_LEN);
        printf("Destination PORT Number  : ");
        print_port(tcp->dport);
        printf("Source PORT Number       : ");
        print_port(tcp->sport);
        //printf("tcp header Size          : %d bytes\n",TCP_LEN);

          //PRINT PAYLOAD
          printf("===========DATA print============\n");
          int PL_LEN = header->caplen - ETHER_LEN - IP_LEN - TCP_LEN;
          payload = (u_char *) (packet + ETHER_LEN + IP_LEN + TCP_LEN);
          printf("payload Data          : ");
          if(PL_LEN > 10){PL_LEN =10;}
          for (int i=0;(PL_LEN) >=i;i++) {
              printf("%02X ",payload[i]);
          }
        }
      }
    }

  pcap_close(handle);
  return 0;
}
