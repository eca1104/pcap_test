#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

struct ethernet_header
{
    u_int8_t ether_dmac[6];
    u_int8_t ether_smac[6];
    u_int16_t ether_type;

};

struct ip_header
{
    u_int8_t val; //version and length
    u_int8_t dsf;
    u_int16_t total_length;
    u_int16_t identifi;
    u_int16_t flags;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check_sum;
    u_int8_t ip_srcaddr[4];
    u_int8_t ip_destaddr[4];

};

struct tcp_header
{
    u_int16_t sport;
    u_int16_t dport;
    u_int8_t seq_num[4];
    u_int8_t ack_num[4];
    u_int16_t flags; // header length and flags
    u_int16_t ws; //window size
    u_int16_t cs; //checksum
    u_int16_t urgent;
};
struct payload
{
    u_char http_data[10];
};

u_int16_t my_ntohs(uint16_t n){
   return n>>8 | n<<8;
}


void print_ethernet(const unsigned char *data){

struct ethernet_header *ether;
ether=(struct ethernet_header *)data;
u_int16_t ether_type;
ether_type=my_ntohs(ether->ether_type);
if(ether_type == 0x0800)
{

   printf ("\nDest Mac=");
    for(int i=0;i<=5;i++)
    {
        printf("%02X", ether->ether_dmac[i]);
        if(i!=5)
        {
            printf(":");
        }

    }
    printf ("\nSrc Mac=");
     for(int i=0;i<=5;i++)
     {
         printf("%02X", ether->ether_smac[i]);
         if(i!=5)
         {
             printf(":");
         }

     }
}
}
void print_ip(const unsigned char *data)
{
    struct ip_header *iph;
    iph = (struct ip_header *)data;

    if(iph->protocol != 0x60){


    printf("\nDest IP=");
    for(int i=0;i<=3;i++)
    {
        printf("%u", iph->ip_destaddr[i]);
        if(i!=3)
        {
            printf(".");
        }

    }
    printf ("\nSrc IP=");
     for(int i=0;i<=3;i++)
     {
         printf("%u", iph->ip_srcaddr[i]);
         if(i!=3)
         {
             printf(".");
         }

     }

}
}

void print_tcp(const unsigned char *data){
    struct tcp_header *th;
    th = (struct tcp_header *)data;

    printf("\nDest Port=%d",my_ntohs(th->dport));
    printf("\nSrc Port=%d",my_ntohs(th->sport));
    printf("\n");

 }
void print_data(const unsigned char *data){
    struct payload *pay;
    pay = (struct payload *)data;
    printf("\n");

    printf ("\n%s\n ",pay->http_data);

    printf("\n========END========\n");
}


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
  const u_char* data;
  struct ip_header *iph;
  int ip_length=0;

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
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("\n========START========\n");
    print_ethernet(packet);
    data=packet+sizeof(struct ethernet_header);
    print_ip(data);

    iph = (struct ip_header *)data;
    ip_length=(iph->val)&0x0F;
    ip_length=ip_length*4;
    data=data+ip_length;
    print_tcp(data);
    data=data+sizeof(struct tcp_header);
    print_data(data);

  }

  pcap_close(handle);
  return 0;
}

