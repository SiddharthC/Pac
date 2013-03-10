#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

int counter = 0;

/*
Handle IP Packets
*/

u_char *handle_IP
(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);

/*
IP Header
*/
struct my_ip
{
    u_int8_t ip_vhl;    /* header length, version */
#define IP_V(ip) (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)
    u_int8_t ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
    u_int8_t ip_ttl;
    u_int8_t ip_p;
    u_int16_t ip_sum;
    struct in_addr ip_src, ip_dst;
};


/* Looking at IP Headers */
void my_callback(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    u_char *type_ip = handle_IP(args, pkthdr, packet);
}

/* Function to handle IP Packets*/
u_char *handle_IP
(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    const struct my_ip *ip;
    u_int length = pkthdr->len;
    u_int hlen, off, version;
    int i;
    int len;
    /* jump pass the ethernet header */
    ip = (struct my_ip *)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);
    /* check to see we have a packet of valid length */
    if (length < sizeof(struct my_ip))
    {
        printf("truncated ip %d", length);
        return NULL;
    }
    len = ntohs(ip->ip_len);
    hlen = IP_HL(ip); /* header length */
    version = IP_V(ip);/* ip version */
    /* check version */
    if (version != 4)
    {
        fprintf(stdout, "Unknown version %d\n", version);
        return NULL;
    }
    /* check header length */
    if (hlen < 5 )
    {
        fprintf(stdout, "bad-hlen %d \n", hlen);
    }
    /* see if we have as much packet as we should */
    if (length < len)
        printf("\ntruncated IP - %d bytes missing\n", len - length);
    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);

    /* Print details of packets only from 192.168.64.2*/
    if ((off && 0x1fff) == 0 && !strcmp(inet_ntoa(ip->ip_src), "192.168.64.2"))
    {
        /* print SOURCE and DESTINATION IPs*/
        fprintf(stdout, "Source IP: ");
        fprintf(stdout, "%s ",
                inet_ntoa(ip->ip_src));
        fprintf(stdout, " Destination IP: %s \n",
                inet_ntoa(ip->ip_dst));
        counter++;
    }
    return NULL;
}

/*MAIN*/
int main(int argc, char **argv)
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    struct bpf_program fp;  // hold compiled program
    bpf_u_int32 maskp;  // subnet mask
    bpf_u_int32 netp;   // ip
    u_char *args = NULL;

    if (argc < 2)
    {
        fprintf(stdout, "Usage: %s numpackets \"options\"\n", argv[0]);
        return 0;
    }

    /* grab a device to read from ... */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    pcap_lookupnet(dev, &netp, &maskp, errbuf);
    descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
    if (descr == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }
    if (argc > 2)
    {
        if (pcap_compile(descr, &fp, argv[2], 0, netp) == -1)
        {
            fprintf(stderr, "Error calling pcap_compile\n");
            exit(1);
        }
        /* set the compiled program as the filter */
        if (pcap_setfilter(descr, &fp) == -1)
        {
            fprintf(stderr, "Error setting filter\n");
            exit(1);
        }
    }
    pcap_loop(descr, atoi(argv[1]), my_callback, args);
    fprintf(stdout, "\n Total Packets captured from 192.168.64.2 = %d\n", counter);
    return 0;
}


