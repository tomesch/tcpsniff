#include "tcpsniff.h"

int main(int argc, char *argv[]){
	char * iflag=NULL;
	char * oflag;
	char * fflag;
	int vflag, pflag=0;
	int c;

	while ((c = getopt (argc, argv, "i:o:f:v:p")) != -1){
		switch(c){
			case 'p' : // promiscuous mode 
				pflag = 1;
				break;
			case 'i' : // interface to listen on
				iflag = strdup(optarg);
				break;
			case 'o' : // log file
				oflag = strdup(optarg);
				break;
			case 'f' : // BPF filer
				fflag = strdup(optarg);
				break;
			case 'v' : // verbosity level
				vflag = atoi(optarg);
				break;
			default:
				break;
		}
	}
	
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t * capture_handle;

	if(iflag==NULL){
		if ((iflag = pcap_lookupdev(error_buffer))==NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", error_buffer);
			print_all_devices();
			exit(1);
		}
	}	

	if((capture_handle = pcap_create(iflag, error_buffer))==NULL){
		fprintf(stderr,"Error in pcap_create: %s\n", error_buffer);
		exit(1);
	}

	pcap_set_snaplen(capture_handle,CAPTURESIZE);
	if(pflag==1){
		pcap_set_promisc(capture_handle, 1);
	}

	if((pcap_activate(capture_handle) == PCAP_ERROR_NO_SUCH_DEVICE)){
		printf("Device (%s) does not exist\n",iflag);
		printf("The following devices are available : \n");
		print_all_devices();
		exit(0);
	}

	printf("listening on %s, capture size %d bytes\n",iflag,CAPTURESIZE);
	if((pcap_loop(capture_handle, 0, (pcap_handler)got_packet, NULL))==-1){
		char *prefix = "Error in pcap_loop: ";
		pcap_perror(capture_handle, prefix);
		printf("Error in loop\n");
	}

	pcap_close(capture_handle);
    	return 0;
}

void print_header_telnet(const u_char *packet){
	printf("|----> TELNET\n");
}
void print_header_http(const u_char *packet){
	printf("|----> HTTP\n");
}
void print_header_https(const u_char *packet){
	printf("|----> HTTPS\n");
}
void print_header_ftp(const u_char *packet){
	printf("|----> FTP\n");
}
void print_header_smtp(const u_char *packet){
	printf("|----> SMTP\n");
}
char * get_tcp_flags(struct tcphdr *tcp){
	char str[100];
	strcpy(str,"");
	if(tcp->fin==1){
		strcat(str,"FIN, ");
	}
	if(tcp->syn==1){
		strcat(str,"SYN, ");
	}
	if(tcp->rst==1){
		strcat(str,"RST, ");
	}
	if(tcp->psh==1){
		strcat(str,"PSH, ");
	}
	if(tcp->ack==1){
		strcat(str,"ACK, ");
	}
	if(tcp->urg==1){
		strcat(str,"URG, ");
	}
	return strdup(str);
}
void print_header_tcp(const u_char *packet){
	printf("|---> TCP ");
	struct tcphdr *tcp;
	tcp = (struct tcphdr*)packet;
	char * flags = get_tcp_flags(tcp);
	if(strlen(flags) > 2){
		flags[strlen(flags)-2] = '\0';	
	}
	printf("%d > %d, Flags : [%s] \n",ntohs(tcp->source), ntohs(tcp->dest),flags);

	switch(ntohs(tcp->source)){
		case 80:
			print_header_http(packet);
			break;
		case 443:
			print_header_https(packet);
			break;
		case 20:
			print_header_ftp(packet);
			break;
		case 21:
			print_header_ftp(packet);
			break;
		case 23:
			print_header_telnet(packet);
			break;
		case 25:
			print_header_smtp(packet);
			break;	
		default:
			switch(ntohs(tcp->dest)){
				case 80:
					print_header_http(packet);
					break;
				case 443:
					print_header_https(packet);
					break;
				case 20:
					print_header_ftp(packet);
					break;
				case 21:
					print_header_ftp(packet);
					break;
				case 23:
					print_header_telnet(packet);
					break;
				case 25:
					print_header_smtp(packet);
					break;	
				default:
					break;
			}
	}
}
void print_header_bootp(const u_char *packet){
	char magic_cookie[4] = VM_RFC1048;	
	printf("|----> BOOTP ");
	struct bootp *bootp;
	struct vend *vendor;
	bootp = (struct bootp*) packet;
	vendor = (struct vend*) bootp->bp_vend;

	if(strncmp(vendor->v_magic,magic_cookie,4)==0){
		// Vendor specific options available
	}

}
void print_header_dns(const u_char *packet){
	printf("|----> DNS\n");
}
void print_header_udp(const u_char *packet){
	printf("|---> UDP ");
	struct udphdr *udp;
	udp = (struct udphdr*)packet;
	printf("%d > %d\n",ntohs(udp->source),ntohs(udp->dest));

	switch(ntohs(udp->source)){
		case 67:
			print_header_bootp((packet+sizeof(struct udphdr)));
			break;
		case 68:
			print_header_bootp((packet+sizeof(struct udphdr)));
			break;
		case 53:
			print_header_dns((packet+sizeof(struct udphdr)));
			break;
		default:
			switch(ntohs(udp->dest)){
				case 67:
					print_header_bootp((packet+sizeof(struct udphdr)));
					break;
				case 68:
					print_header_bootp((packet+sizeof(struct udphdr)));
					break;
				case 53:
					print_header_dns((packet+sizeof(struct udphdr)));
					break;	
				default:
					break;
			}
	}
}

void print_header_ip(const u_char *packet){
	struct ip *ip_header; 
	ip_header = (struct ip*)packet;
	char src[INET_ADDRSTRLEN];
	char dst[INET_ADDRSTRLEN];
	int version = ip_header->ip_v;
	inet_ntop(AF_INET,&(ip_header->ip_src),src,INET_ADDRSTRLEN);
	inet_ntop(AF_INET,&(ip_header->ip_dst),dst,INET_ADDRSTRLEN);
	printf("|--> IPv%d %s > %s, Length : %d, TTL : %d \n",version,src,dst,ip_header->ip_len,ip_header->ip_ttl);

	switch(ip_header->ip_p){
		case 6:
			print_header_tcp((packet+sizeof(struct ip)));
			break;
		case 17:
			print_header_udp((packet+sizeof(struct ip)));
			break;
		default:
			break; 
	}
}

void print_header_arp(const u_char *packet){
	struct arphdr *arp;
	arp = (struct arphdr*) packet;
	u_char * dstip;
	u_char * srcip;
	char dstip_r[INET_ADDRSTRLEN];
	int hl, pl;
	hl = arp->ar_hln;
	pl = arp->ar_pln;
	
	switch(pl){
		case 4:
			dstip = malloc(4*sizeof(u_char));
			srcip = malloc(4*sizeof(u_char));
			strncpy(dstip,arp->ar_op+sizeof(u_short)+(2*hl*sizeof(u_char))+pl*sizeof(u_char),4*sizeof(u_char));
			break;
		case 16:
			dstip = malloc(16*sizeof(u_char));
			srcip = malloc(16*sizeof(u_char));
			break;
		default:
			break;
	}	

	inet_ntop(AF_INET,&(dstip),dstip_r,INET_ADDRSTRLEN);
	printf("|--> ");
	switch(ntohs(arp->ar_op)){
		case ARPOP_REQUEST:
			printf("ARP request who has %s",dstip_r);
			break;
		case ARPOP_REPLY:
			printf("ARP reply");
			break;
		case ARPOP_RREQUEST:
			printf("RARP request");
			break;
		case ARPOP_RREPLY:
			printf("RARP reply");
			break;
		case ARPOP_InREQUEST:
			printf("InARP request");
			break;
		case ARPOP_InREPLY:
			printf("InARP reply");
			break;
		case ARPOP_NAK:
			printf("ARP NAK");
			break;
		default:
			break;
	}
	printf("\n");
}

void got_packet(u_char *user, const struct pcap_pkthdr *phrd, const u_char *packet){
	struct timeval tv = phrd->ts; 
	struct tm* ptm; 
	char time_string[40]; 
	long milliseconds; 
	gettimeofday (&tv, NULL); 
	ptm = (struct tm*) localtime (&tv.tv_sec); 
	strftime (time_string, sizeof (time_string), "%H:%M:%S", ptm); 
	milliseconds = tv.tv_usec; 
	printf("%s.%03ld\n", time_string, milliseconds); 

	struct ether_header *ethernet; 
	ethernet = (struct ether_header*)packet;
	printf("|-> Ethernet ");
	u_char *ptr;
	int i;
	ptr = ethernet->ether_dhost;
	i = ETHER_ADDR_LEN;
	do{
	printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
	}while(--i>0);

	ptr = ethernet->ether_shost;
	i = ETHER_ADDR_LEN;
	printf(" >");
	do{
	printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
	}while(--i>0);
	printf("\n");
	
	switch(ntohs(ethernet->ether_type)){
		case 0x0800:
			print_header_ip((packet+sizeof(struct ether_header)));
			break;
		case 0x0806:
			print_header_arp((packet+sizeof(struct ether_header)));
			break;
		default:
			break; 	
	}	
	printf("\n");
}
void print_all_devices(){
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	if (pcap_findalldevs(&alldevs, error_buffer) == -1){
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", error_buffer);
        exit(1);
    }
    for(alldevs; alldevs != NULL; alldevs= alldevs->next){
        printf("%s\n", alldevs->name);
    }
}
