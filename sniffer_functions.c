#include "header.h"

//Packet handleing functions
/* looking at ethernet headers */
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;


void print_hex_ascii_line(const u_char *payload, int len, int offset) // Function to convert hex to ASCII
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
void print_payload(const u_char *payload, int len) // Function to print the contents of packet
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
/*
param1@ the udp header, struct in header.h
param2@ the ethernet header, lvl2 OSI, part of the pcap library
param3@ the ip header, lvl3 OSI, struct found in header.h
param4@ char array containing the packets payload
param5@ char array that will hold our reconstructed packet
param6@ the total amount of bytes we need to allocate for packet
param7@ size in bytes of the ip header
param8@ size in bytes of the payload
*/
void buildPacket(struct sniff_udp *udp,struct ether_header *ethh, // function to assemble packet from the structures we've modified
	 struct my_ip *ip, const char *payload,	u_char *buffer,size_t bufferLen,
	 size_t ipSize, size_t payloadSize)
{
	//print_payload(payload,payloadSize);
		printf("buf len check: %d \n", bufferLen); // checks the total size of the buffer
    memset(buffer,0, bufferLen+1); // allocates memory for the new packet
  	memcpy(buffer, ethh, SIZE_ETHERNET); // copies the bytes form the eth hdr into the new packet
		memcpy(buffer+SIZE_ETHERNET,ip,ipSize); // copies the bytes from the ip header into the new packet, starting where the eth hdr left off
		memcpy(buffer+SIZE_ETHERNET+ipSize, udp, SIZE_UDP); // continues to fill the packet
		memcpy(buffer+SIZE_ETHERNET+ipSize+SIZE_UDP, payload, payloadSize); // adds payload to the end of the packet
		print_payload(buffer, bufferLen); // takes a look at the packet we've just creeated
		return;
}
// param1@ ethernet header struct
void getHMac(struct ether_header *myMac) // function to change the source mac of the packet to our mac
{
    int s;
    struct ifreq buffer; // mac addr struct
    s = socket(PF_INET, SOCK_DGRAM, 0); // opens a socket with the neccesary protocols

    memset(&buffer, 0x00, sizeof(buffer)); // gives buffer a block of memory

    strcpy(buffer.ifr_name, "enp0s3"); // sets the interface name to the interface we want to use, IMPORTANT must be changed to the interface you want to use.

    ioctl(s, SIOCGIFHWADDR, &buffer); // gets the mac address of our interface

    close(s); // closes socket that we no longer need

    memcpy(myMac->ether_shost,buffer.ifr_hwaddr.sa_data,6); // copies the memory from our struct to the packet we have captured and dissected
    printf("\n");
    return;
}
//param1@ ip header struct
void getHip(struct my_ip *ip) // function to change the source ip of our captured packet to our own ip
{
  struct addrinfo hints;
  struct addrinfo *servinfo; // will point to the results
  memset(&hints, 0, sizeof(hints)); // make sure the struct is empty

  int status;
if((status=getaddrinfo("ben-VirtualBox",NULL,&hints,&servinfo))!=0) // gets address of host system // IMPORTANT!!! requires the hostname of the local system as the first argument
  {
    printf("status is %d \n",status);
    fprintf(stdout, "getaddrinfo: %s \n",gai_strerror(status));
    exit(1);
  }
  struct sockaddr *tmp=servinfo->ai_addr; // creates a temporary struct to store the address
  ip->ip_src=((struct sockaddr_in*)tmp)->sin_addr; // move the memory from our tmp struct to the packet memory
  freeaddrinfo(servinfo); // frees the linked list
}
/*
param1@ the buffer storing our reconstructed packet
param2@ char array holding the dst address, purely for asthetic purposes
param3@ size of the reconstructed packet in bytes
*/
void sendPacket(u_char *buffer,const u_char *dstAddr, size_t bufferLen) // sends the packet we constructed onto the wire
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i;
	if ( (fp= pcap_open_live("enp0s3",   //opens the raw socket         // name of the device
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
		if ((numbytes=pcap_inject(fp, &buffer,bufferLen /* size */)) == -1) // sends the packet without the kernel messing with the headers in our paacket
    {
       fprintf(stdout,"Error sending the packet:%s \n", pcap_geterr(fp));
        return;
    }
		printf("sent %d bytes\n",numbytes); // error check
    return;
}
u_char* handle_IP // extracts the ip header from the packet and includes all modification and transmission functions
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
    ip = (struct my_ip*)(packet + sizeof(struct ether_header)); // puts the ip hdr from the cp into a more usable struct
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
        fprintf(stdout,"%s header length:%d version:%d  length:%d  offset%d\n",
                inet_ntoa(ip->ip_dst),
                hlen,version,len,off);
				dstAddr=inet_ntoa(ip->ip_dst);

        // prints to file
        fprintf(logfile,"IP: ");
        fprintf(logfile,"%s ",
                inet_ntoa(ip->ip_src));
        fprintf(logfile,"%s header length:%d version:%d  length:%d  offset%d\n",
                inet_ntoa(ip->ip_dst),
                hlen,version,len,off);
        getHip(ip); // changes the packets mac to our own

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
      udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + SIZE_UDP); // puts the protocol header into a more usable struct

	     printf("   Src port: %d\n", ntohs(udp->uh_sport));
	     printf("   Dst port: %d\n", ntohs(udp->uh_dport));

	/* define/compute udp payload (segment) offset */
	     payload = (u_char *)(packet + SIZE_ETHERNET + SIZE_UDP + hlen); // puts the payload into a readable buffer

	/* compute udp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (hlen + SIZE_UDP);
         if (size_payload > ntohs(udp->uh_ulen))
                 size_payload = ntohs(udp->uh_ulen);
	printf("payload size is %d\n",size_payload );
  print_payload(payload, size_payload);
	size_t bufferLen=(SIZE_UDP+SIZE_ETHERNET+hlen+size_payload); // sets the size of our new packet to include all headers and the payload
	u_char buffer[bufferLen+1];// defines and allocates memort
	buildPacket(udp, eptr,ip,payload,buffer,bufferLen, hlen,size_payload);// fills the new packet
	sendPacket(buffer, dstAddr, bufferLen); // sends the new packet
    fclose(logfile); // close the log file
    return NULL;
  }
}

/* handle ethernet packets, uses
 * print-ether.c from tcpdump source as a referance
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
