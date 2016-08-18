#include "header.h"

//Packet handleing functions
/* looking at ethernet headers */
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;


void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}
void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}
void buildPacket(struct sniff_udp *udp,struct ether_header *ethh,
	 struct my_ip *ip, const char *payload,	u_char *buffer,size_t bufferLen,
	 size_t ipSize, size_t payloadSize)
{
	//print_payload(payload,payloadSize);
		printf("buf len check: %d \n", bufferLen);
    memset(buffer,0, bufferLen+1);
  	memcpy(buffer, ethh, SIZE_ETHERNET);
		memcpy(buffer+SIZE_ETHERNET,ip,ipSize);
		memcpy(buffer+SIZE_ETHERNET+ipSize, udp, SIZE_UDP);
		memcpy(buffer+SIZE_ETHERNET+ipSize+SIZE_UDP, payload, payloadSize);
		print_payload(buffer, bufferLen);
		return;
}
void getHMac(struct ether_header *myMac)
{
    int s;
    struct ifreq buffer;
    s = socket(PF_INET, SOCK_DGRAM, 0);

    memset(&buffer, 0x00, sizeof(buffer));

    strcpy(buffer.ifr_name, "enp0s3");

    ioctl(s, SIOCGIFHWADDR, &buffer);

    close(s);

    strcpy(myMac->ether_shost,buffer.ifr_hwaddr.sa_data);
    printf("\n");
    return;
}
void getHip(struct my_ip *ip)
{
  struct addrinfo hints;
  struct addrinfo *servinfo; // will point to the results
  memset(&hints, 0, sizeof(hints)); // make sure the struct is empty

  int status;
if((status=getaddrinfo("ben-VirtualBox",NULL,&hints,&servinfo))!=0) // gets address of host system
  {
    printf("status is %d \n",status);
    fprintf(stdout, "getaddrinfo: %s \n",gai_strerror(status));
    exit(1);
  }
  struct sockaddr *tmp=servinfo->ai_addr;
  ip->ip_src=((struct sockaddr_in*)tmp)->sin_addr;
  freeaddrinfo(servinfo);
}
void sendPacket(u_char *buffer,const u_char *dstAddr, size_t bufferLen)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i;
	if ( (fp= pcap_open_live("enp0s3",            // name of the device
                        BUFSIZ,                // portion of the packet to capture (only the first 100 bytes)
                        1,  // promiscuous mode
                        1000,               // read timeout
                        errbuf              // error buffer
                        ) ) == NULL)
    {
        printf("Unable to open the adapter\n");
        return;
    }
		int numbytes;
		if ((numbytes=pcap_inject(fp, &buffer,bufferLen /* size */)) == -1)
    {
       fprintf(stdout,"Error sending the packet:%s \n", pcap_geterr(fp));
        return;
    }
		printf("sent %d bytes to %u \n",numbytes, (*dstAddr));
    return;
}
u_char* handle_IP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
	  struct ether_header *eptr;
		eptr = (struct ether_header *) packet;
    struct my_ip* ip;
    struct sniff_udp* udp;
    const char *payload; /* Packet payload */
		u_char *buffer;
		const u_char *dstAddr;
		u_int length = pkthdr->len;
    u_int hlen,off,version;
    int i;

    int size_payload;
    int len;
    logfile=fopen("log.txt","a");
		printf("Packet recived is %d bytes long\n",sizeof(packet));
    /* jump pass the ethernet header */
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);

    /* check to see we have a packet of valid length */
    if (length < sizeof(struct my_ip))
    {
        printf("truncated ip %d",length);
        return NULL;
    }

    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip)*4; /* header length */
    version = IP_V(ip);/* ip version */

    /* check version */
    if(version != 4)
    {
      fprintf(stdout,"Unknown version %d\n",version);
      return NULL;
    }

    /* check header length */
    if(hlen < 20 )
    {
        fprintf(stdout,"bad-hlen %d \n",hlen);
    }

    /* see if we have as much packet as we should */
    if(length < len)
        printf("\ntruncated IP - %d bytes missing\n",len - length);

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0 )/* aka no 1's in first 13 bits */
    {/* print SOURCE DESTINATION hlen version len offset */
        fprintf(stdout,"IP: ");
        fprintf(stdout,"%s ",
                inet_ntoa(ip->ip_src));
        fprintf(stdout,"%s %d %d %d %d\n",
                inet_ntoa(ip->ip_dst),
                hlen,version,len,off);
				dstAddr=inet_ntoa(ip->ip_dst);

        // prints to file
        fprintf(logfile,"IP: ");
        fprintf(logfile,"%s ",
                inet_ntoa(ip->ip_src));
        fprintf(logfile,"%s %d %d %d %d\n",
                inet_ntoa(ip->ip_dst),
                hlen,version,len,off);
        getHip(ip);
        switch(ip->ip_p) // checks protocol is udp
        {
        		case IPPROTO_TCP:
        			printf("   Protocol: TCP\n");
        			exit(1);
        		case IPPROTO_UDP:
        			printf("   Protocol: UDP\n");
        			break;
        		case IPPROTO_ICMP:
        			printf("   Protocol: ICMP\n");
        			exit(1);
        		case IPPROTO_IP:
        			printf("   Protocol: IP\n");
        			exit(1);
        		default:
        			printf("   Protocol: unknown\n");
        			exit(1);
      }
      udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + SIZE_UDP);

	     printf("   Src port: %d\n", ntohs(udp->uh_sport));
	     printf("   Dst port: %d\n", ntohs(udp->uh_dport));

	/* define/compute udp payload (segment) offset */
	     payload = (u_char *)(packet + SIZE_ETHERNET + SIZE_UDP + hlen);

	/* compute udp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (hlen + SIZE_UDP);
         if (size_payload > ntohs(udp->uh_ulen))
                 size_payload = ntohs(udp->uh_ulen);
	printf("payload size is %d\n",size_payload );
  print_payload(payload, size_payload);
	size_t bufferLen=(SIZE_UDP+SIZE_ETHERNET+hlen+size_payload);
	u_char buffer[bufferLen+1];
	buildPacket(udp, eptr,ip,payload,buffer,bufferLen, hlen,size_payload);
	sendPacket(buffer, dstAddr, bufferLen);
    fclose(logfile);
    return NULL;
  }
}

/* handle ethernet packets, much of this code gleaned from
 * print-ether.c from tcpdump source
 */
u_int16_t handle_ethernet
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    struct ether_header *eptr;  /* net/ethernet.h */
    u_short ether_type;

    if (caplen < ETHER_HDRLEN)
    {
        fprintf(stdout,"Packet length less than ethernet header length\n");
        return -1;
    }

    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);

    /* Lets print SOURCE DEST TYPE LENGTH */
    fprintf(stdout,"ETH: ");
    fprintf(stdout,"%s "
            ,ether_ntoa((struct ether_addr*)eptr->ether_shost));
    fprintf(stdout,"%s "
            ,ether_ntoa((struct ether_addr*)eptr->ether_dhost));
            // print to file
    logfile=fopen("log.txt","a");
    fprintf(logfile,"ETH: ");
    fprintf(logfile,"%s "
                    ,ether_ntoa((struct ether_addr*)eptr->ether_shost
                  ));
    fprintf(logfile,"%s "
                    ,ether_ntoa((struct ether_addr*)eptr->ether_dhost));
    getHMac(eptr);
    /* check to see if we have an ip packet */
    if (ether_type == ETHERTYPE_IP)
    {
        fprintf(stdout,"(IP)");
        fprintf(logfile, "(IP)");
    }else  if (ether_type == ETHERTYPE_ARP)
    {
        fprintf(stdout,"(ARP)");
        fprintf(logfile,"(ARP)");
    }else  if (eptr->ether_type == ETHERTYPE_REVARP)
    {
        fprintf(stdout,"(RARP)");
        fprintf(logfile,"(RARP)");
    }else {
        fprintf(stdout,"(?)");
        fprintf(logfile,"(?)");
    }
    fprintf(stdout," %d\n",length);
    fprintf(logfile," %d\n",length);
    fclose(logfile);

    return ether_type;
}
// Functions for formating, sorting and displaying packet and network info
void ProcessPacket(const u_char* buffer, int size)
{
    //Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)buffer;
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
            print_icmp_packet(buffer,size);
            break;

        case 2:  //IGMP Protocol
            ++igmp;
            break;

        case 6:  //TCP Protocol
            ++tcp;
            print_tcp_packet(buffer , size);
            break;

        case 17: //UDP Protocol
            ++udp;
            print_udp_packet(buffer , size);
            break;

        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r",tcp,udp,icmp,igmp,others,total);
}

void print_ip_header(const u_char* Buffer, int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen =iph->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(logfile,"\n");
    fprintf(logfile,"IP Header\n");
    fprintf(logfile,"   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile,"   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(logfile,"   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile,"   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile,"   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(logfile,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile,"   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile,"   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile,"   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(const u_char* Buffer, int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;

    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);

    fprintf(logfile,"\n\n***********************TCP Packet*************************\n");

    print_ip_header(Buffer,Size);

    fprintf(logfile,"\n");
    fprintf(logfile,"TCP Header\n");
    fprintf(logfile,"   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile,"   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile,"   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile,"   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile,"   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile,"   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(logfile,"   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile,"   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile,"   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile,"   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile,"   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile,"   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile,"   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile,"   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile,"   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile,"\n");
    fprintf(logfile,"                        DATA Dump                         ");
    fprintf(logfile,"\n");

    fprintf(logfile,"IP Header\n");
    PrintData(Buffer,iphdrlen);

    fprintf(logfile,"TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);

    fprintf(logfile,"Data Payload\n");
    PrintData(Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4) );

    fprintf(logfile,"\n###########################################################");
}

void print_udp_packet(const u_char *Buffer , int Size)
{

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;

    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen);

    fprintf(logfile,"\n\n***********************UDP Packet*************************\n");

    print_ip_header(Buffer,Size);

    fprintf(logfile,"\nUDP Header\n");
    fprintf(logfile,"   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile,"   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile,"   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(logfile,"   |-UDP Checksum     : %d\n" , ntohs(udph->check));

    fprintf(logfile,"\n");
    fprintf(logfile,"IP Header\n");
    PrintData(Buffer , iphdrlen);

    fprintf(logfile,"UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);

    fprintf(logfile,"Data Payload\n");
    PrintData(Buffer + iphdrlen + sizeof udph ,( Size - sizeof udph - iph->ihl * 4 ));

    fprintf(logfile,"\n###########################################################");
}

void print_icmp_packet(const u_char* Buffer , int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;

    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen);

    fprintf(logfile,"\n\n***********************ICMP Packet*************************\n");

    print_ip_header(Buffer , Size);

    fprintf(logfile,"\n");

    fprintf(logfile,"ICMP Header\n");
    fprintf(logfile,"   |-Type : %d",(unsigned int)(icmph->type));

    if((unsigned int)(icmph->type) == 11)
        fprintf(logfile,"  (TTL Expired)\n");
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
        fprintf(logfile,"  (ICMP Echo Reply)\n");
    fprintf(logfile,"   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(logfile,"   |-Checksum : %d\n",ntohs(icmph->checksum));
    //fprintf(logfile,"   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(logfile,"   |-Sequence : %d\n",ntohs(icmph->sequence));
    fprintf(logfile,"\n");

    fprintf(logfile,"IP Header\n");
    PrintData(Buffer,iphdrlen);

    fprintf(logfile,"UDP Header\n");
    PrintData(Buffer + iphdrlen , sizeof icmph);

    fprintf(logfile,"Data Payload\n");
    PrintData(Buffer + iphdrlen + sizeof icmph , (Size - sizeof icmph - iph->ihl * 4));

    fprintf(logfile,"\n###########################################################");
}

void PrintData (const u_char* data , int Size)
{

    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile,"         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet

                else fprintf(logfile,"."); //otherwise print a dot
            }
            fprintf(logfile,"\n");
        }

        if(i%16==0) fprintf(logfile,"   ");
            fprintf(logfile," %02X",(unsigned int)data[i]);

        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) fprintf(logfile,"   "); //extra spaces

            fprintf(logfile,"         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) fprintf(logfile,"%c",(unsigned char)data[j]);
                else fprintf(logfile,".");
            }
            fprintf(logfile,"\n");
        }
    }
}
