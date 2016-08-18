#define _SVID_SOURCE
#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //memset
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<net/if.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <unistd.h> // for close
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <pcap.h>
#include <netdb.h>
#include <ctype.h>


/* tcpdump header (ether.h) defines ETHER_HDRLEN) */


// Structs
/*
 * Structure of an internet header, naked of options.
 *
 *
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */

 struct my_ip
 {
 	u_int8_t	ip_vhl;		/* header length, version */
 #define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
 #define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
 	u_int8_t	ip_tos;		/* type of service */
 	u_int16_t	ip_len;		/* total length */
 	u_int16_t	ip_id;		/* identification */
 	u_int16_t	ip_off;		/* fragment offset field */
 #define	IP_DF 0x4000			/* dont fragment flag */
 #define	IP_MF 0x2000			/* more fragments flag */
 #define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
 	u_int8_t	ip_ttl;		/* time to live */
 	u_int8_t	ip_p;		/* protocol */
 	u_int16_t	ip_sum;		/* checksum */
 	struct	in_addr ip_src,ip_dst;	/* source and dest address */
 };
 /* UDP header */

struct sniff_udp
{
         u_short uh_sport;               /* source port */
         u_short uh_dport;               /* destination port */
         u_short uh_ulen;                /* udp length */
         u_short uh_sum;                 /* udp checksum */

};

#define SIZE_UDP        8               /* length of UDP header */
#define SIZE_ETHERNET 14                /*length of ethernet header*/

//Function definitions
void ProcessPacket(const u_char* , int);
void print_ip_header(const u_char* , int);
void print_tcp_packet(const u_char* , int);
void print_udp_packet(const u_char * , int);
void print_icmp_packet(const u_char* , int);
void PrintData (const u_char* , int);
u_int16_t handle_ethernet
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet);
u_char* handle_IP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet);

// Global vars

int sock_raw;
FILE *logfile;
struct sockaddr_in source,dest;
