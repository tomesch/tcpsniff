#include "tcpsniff.h"

int main(int argc, char *argv[]){
	char * iflag=NULL;
	char * oflag=NULL;
	char * fflag=NULL;
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
			case 'o' : // offline mode
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
	
	if(oflag==NULL){ // live mode
		if(iflag==NULL){ // if no device is specified
			// looking for default device
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

		if(pflag==1){ // set the device to promiscuous mode
			pcap_set_promisc(capture_handle, 1);
		}

		if((pcap_activate(capture_handle) == PCAP_ERROR_NO_SUCH_DEVICE)){
			printf("Device (%s) does not exist\n",iflag);
			printf("The following devices are available : \n");
			print_all_devices();
			exit(0);
		}
		
		if(fflag!=NULL){ // find netmask, compile BPF and apply it
			struct bpf_program fp;
			bpf_u_int32 netmask;
			bpf_u_int32 network;

			if(pcap_lookupnet(iflag,&network,&netmask,error_buffer)<0){
				fprintf(stderr,"Error in pcap_lookupnet: %s\n", error_buffer);
				exit(1);	
			}	
			if((pcap_compile(capture_handle,&fp, fflag,0,netmask))<0){
				char *prefix = "Error in pcap_compile";
				pcap_perror(capture_handle, prefix);
				exit(1);
			}
			if(pcap_setfilter(capture_handle,&fp)<0){
				char *prefix = "Error in pcap_setfilter";
				pcap_perror(capture_handle, prefix);
				exit(1);
			}	
		}

		printf("listening on %s, capture size %d bytes\n",iflag,CAPTURESIZE);
	}
	else{ // offline mode
		if((capture_handle = pcap_open_offline(oflag,error_buffer))==NULL){
			fprintf(stderr,"%s\n",error_buffer);
			exit(1);
		}	
	}

	if((pcap_loop(capture_handle, 0, (pcap_handler)got_packet, NULL))==-1){
		char *prefix = "Error in pcap_loop";
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
void get_flags_tcp(struct tcphdr *tcp, char **flags){
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
	if(strlen(str) > 2){
		str[strlen(str)-2] = '\0';	
	}
	*flags = str;
}
void print_header_tcp(const u_char *packet){
	printf("|---> TCP ");
	struct tcphdr *tcp;
	tcp = (struct tcphdr*)packet;
	char * flags;
	get_flags_tcp(tcp,&flags);
	
	printf("%d > %d, Flags : [%s] \n",ntohs(tcp->source), ntohs(tcp->dest),flags);

	switch(ntohs(tcp->source)){
		case HTTPPORT:
			print_header_http(packet);
			break;
		case HTTPSPORT:
			print_header_https(packet);
			break;
		case FTPDATAPORT:
			print_header_ftp(packet);
			break;
		case FTPCONTROLPORT:
			print_header_ftp(packet);
			break;
		case TELNETPORT:
			print_header_telnet(packet);
			break;
		case SMTPPORT:
			print_header_smtp(packet);
			break;	
		default:
			switch(ntohs(tcp->dest)){	
				case HTTPPORT:
					print_header_http(packet);
					break;
				case HTTPSPORT:
					print_header_https(packet);
					break;
				case FTPDATAPORT:
					print_header_ftp(packet);
					break;
				case FTPCONTROLPORT:
					print_header_ftp(packet);
					break;
				case TELNETPORT:
					print_header_telnet(packet);
					break;
				case SMTPPORT:
					print_header_smtp(packet);
					break;	
				default:
					break;
			}
	}
}
void printAscii(u_char *packet, int length){
    
	/*int i;
    int rank =0;
    for(i=0;i< length;i++, rank++){
        if(isprint(packet[i])){
            printf("%c", (packet[i]));
        }
        else if(packet[i] == '\n'){
            printf("%c", (packet[i]));
            rank=0;
        }
        else if(packet[i] == '\r'){
            rank=0;
        }
        else
            printf(".");
        if(rank%64==63)
            printf("\n");
    }
    printf("\n");*/
}
void print_header_bootp(const u_char *packet){
	char magic_cookie[4] = { 99, 130, 83, 99 };	
	struct bootp *bootp;
	struct vend *vendor;
	bootp = (struct bootp*) packet;
	vendor = (struct vend*) bootp->bp_vend;
	char * ip = malloc(100*sizeof(char));
	char * buffer = malloc(100*sizeof(char));
	char dhcp_type[10];
	char dhcp_request[5000];
	char dhcp_options[5000];
	strcpy(dhcp_type,"");	
	strcpy(dhcp_options,"");	
	strcpy(dhcp_request,"");	

	if(strncmp((const char *)vendor->v_magic,(const char *)magic_cookie,4)==0){
		// Vendor specific area
		int i = 4;
		int j;
		while(bootp->bp_vend[i] != 255){
			switch(bootp->bp_vend[i]){
				case TAG_DHCP_MESSAGE:
					switch(bootp->bp_vend[i+2]){
						case DHCPREQUEST:
							strcpy(dhcp_type,"REQUEST");
							break;
						case DHCPDISCOVER:
							strcpy(dhcp_type,"DISCOVER");
							break;
						case DHCPOFFER:
							strcpy(dhcp_type,"OFFER");
							break;
						case DHCPDECLINE:
							strcpy(dhcp_type,"DECLINE");
							break;
						case DHCPACK:
							strcpy(dhcp_type,"ACK");
							break;
						case DHCPNAK:
							strcpy(dhcp_type,"NACK");
							break;
						case DHCPRELEASE:
							strcpy(dhcp_type,"RELEASE");
							break;
						case DHCPINFORM:
							strcpy(dhcp_type,"INFORM");
							break;
						default:
							break;
					}
				break;
				case TAG_PARM_REQUEST:
					for(j=i+3;j<bootp->bp_vend[i+1]+i+2;j++){
						switch(bootp->bp_vend[j]){
							case TAG_GATEWAY:
								strcat(dhcp_request,"router, ");
								break;
							case TAG_DOMAIN_SERVER:
								strcat(dhcp_request,"dns, ");
								break;
							case TAG_DOMAINNAME:
								strcat(dhcp_request,"domain name, ");
								break;
							case TAG_BROAD_ADDR:
								strcat(dhcp_request,"broadcast address, ");
								break;
							case TAG_SUBNET_MASK:
								strcat(dhcp_request,"subnet mask, ");
								break;
							case TAG_TIME_OFFSET:
								strcat(dhcp_request,"time offset, ");
								break;
							case TAG_HOSTNAME:
								strcat(dhcp_request,"hostname, ");
								break;
							case TAG_NETBIOS_NS:
								strcat(dhcp_request,"netbios over TCP/IP name server, ");
								break;
							case TAG_NETBIOS_SCOPE:
								strcat(dhcp_request,"netbios over TCP/IP scope, ");
								break;
							case TAG_REQUESTED_IP:
								strcat(dhcp_request,"requested ip address, ");
								break;
							case TAG_IP_LEASE:
								strcat(dhcp_request,"lease time, ");
								break;
							case TAG_SERVER_ID:
								strcat(dhcp_request,"server id, ");
								break;
							case TAG_PARM_REQUEST:
								strcat(dhcp_request,"PARAMETER_REQUEST_LIST, ");
								break;
							default:
								break;
						}
					}
				break;
				case TAG_GATEWAY:
					sprintf(ip,"       Gateway: %d.%d.%d.%d\n",bootp->bp_vend[i+2],bootp->bp_vend[i+3],bootp->bp_vend[i+4],bootp->bp_vend[i+5]);
					strcat(dhcp_options,ip);
					break;
				case TAG_DOMAIN_SERVER:
					sprintf(ip,"       DNS: %d.%d.%d.%d\n",bootp->bp_vend[i+2],bootp->bp_vend[i+3],bootp->bp_vend[i+4],bootp->bp_vend[i+5]);
					strcat(dhcp_options,ip);
					break;
				case TAG_DOMAINNAME:
					strncpy(buffer,&bootp->bp_vend[i+2],bootp->bp_vend[i+1]);
					buffer[bootp->bp_vend[i+1]] = '\0';
					sprintf(ip,"       Domain name: %s\n",buffer);
					strcat(dhcp_options,ip);
					break;
				case TAG_BROAD_ADDR:
					strcat(dhcp_options,ip);
					break;
				case TAG_SUBNET_MASK:
					sprintf(ip,"       Subnet mask: %d.%d.%d.%d\n",bootp->bp_vend[i+2],bootp->bp_vend[i+3],bootp->bp_vend[i+4],bootp->bp_vend[i+5]);
					strcat(dhcp_options,ip);
					break;
				case TAG_NETBIOS_NS:
					sprintf(ip,"       Netbios NS: %d.%d.%d.%d\n",bootp->bp_vend[i+2],bootp->bp_vend[i+3],bootp->bp_vend[i+4],bootp->bp_vend[i+5]);
					strcat(dhcp_options,ip);
					break;
				case TAG_REQUESTED_IP:
					sprintf(ip,"       Requested IP: %d.%d.%d.%d\n",bootp->bp_vend[i+2],bootp->bp_vend[i+3],bootp->bp_vend[i+4],bootp->bp_vend[i+5]);
					strcat(dhcp_options,ip);
					break;			
				case TAG_IP_LEASE:
					sprintf(ip,"       Lease time: %u seconds\n",bootp->bp_vend[i+2]*256*256*256+bootp->bp_vend[i+3]*256*256+bootp->bp_vend[i+4]*256+bootp->bp_vend[i+5]);
					strcat(dhcp_options,ip);
					break;
				case TAG_SERVER_ID:
					sprintf(ip,"       DHCP Server: %d.%d.%d.%d\n",bootp->bp_vend[i+2],bootp->bp_vend[i+3],bootp->bp_vend[i+4],bootp->bp_vend[i+5]);
					strcat(dhcp_options,ip);
					break;
				default:
					break;  
			}
			i+=2+bootp->bp_vend[i+1];
		}
	}	
	printf("|----> BOOTP\n");
	if(dhcp_type!=NULL){
		printf("       DHCP %s\n",dhcp_type);
		if(strcmp(dhcp_type,"DISCOVER")==0 || strcmp(dhcp_type,"REQUEST")==0){
			printf("       Parameters: %s\n",dhcp_request);
		}
		if(strcmp(dhcp_type,"OFFER")==0 || strcmp(dhcp_type,"ACK")==0){
			printf("%s",dhcp_options);		
		}
	}	
}
void get_flags_dns(uint16_t flags_i, char** qr, char ** opcode, char ** flags){
	// qr
	if((flags_i & (0x8000)) != 0){
		*qr = "response";
	}
	else{
		*qr = "query";
	}
	// opcode
	char opcd = ((flags_i & 0x001E) >> 1);
	switch(opcd){
		case 0:
			*opcode = "Standard query";
			break;	
		case 1:
			*opcode = "Inverse query";
			break;
		case 2:
			*opcode = "Server status request";
			break;
		case 4:
			*opcode = "Notify";
			break;
		case 5:
			*opcode = "Update";
			break;
		default:
			*opcode = "";	
	}	

	//flags
 	char tmp[100]; 
	strcpy(tmp,"");
	if((flags_i & (0x400)) != 0){
		strcat(tmp,"AA, ");
	}
	if((flags_i & (0x200)) != 0){
		strcat(tmp,"TC, ");
	}	
	if((flags_i & (0x100)) != 0){
		strcat(tmp,"RD, ");
	}
	if((flags_i & (0x80)) != 0){
		strcat(tmp,"RA, ");
	}
	if((flags_i & (0x40)) != 0){
		strcat(tmp,"Z, ");
	}
	if((flags_i & (0x20)) != 0){
		strcat(tmp,"AD, ");
	}	
	if((flags_i & (0x10)) != 0){
		strcat(tmp,"CD, ");
	}
	if(strlen(tmp) > 2){
		tmp[strlen(tmp)-2] = '\0';	
	}
	*flags = tmp;
}
void print_header_dns(const u_char *packet){
	struct dnshdr *dns;
	dns = (struct dnshdr*) packet;
	char * qr;
	char * opcode;
	char * flags;
	get_flags_dns(dns->flags,&qr,&opcode,&flags);
	printf("|----> DNS %s (%s), Flags : [%s]\n",qr,opcode,flags);
}

void print_header_udp(const u_char *packet){
	printf("|---> UDP ");
	struct udphdr *udp;
	udp = (struct udphdr*)packet;
	printf("%d > %d\n",ntohs(udp->source),ntohs(udp->dest));

	switch(ntohs(udp->source)){
		case BOOTPSERVERPORT:
			print_header_bootp((packet+sizeof(struct udphdr)));
			break;
		case BOOTPCLIENTPORT:
			print_header_bootp((packet+sizeof(struct udphdr)));
			break;
		case DNSPORT:
			print_header_dns((packet+sizeof(struct udphdr)));
			break;
		default:
			switch(ntohs(udp->dest)){
				case BOOTPSERVERPORT:
					print_header_bootp((packet+sizeof(struct udphdr)));
					break;
				case BOOTPCLIENTPORT:
					print_header_bootp((packet+sizeof(struct udphdr)));
					break;
				case DNSPORT:
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
	char * dstip;
	u_char * srcip;
	char dstip_r[INET_ADDRSTRLEN];
	int hl, pl;
	hl = arp->ar_hln;
	pl = arp->ar_pln;
	
	const char * tpa = (const char *) packet+sizeof(struct arphdr);

	switch(pl){
		case 4:
			dstip = malloc(4*sizeof(u_char));
			srcip = malloc(4*sizeof(u_char));
			strncpy(dstip, tpa, pl);
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
    for(; alldevs != NULL; alldevs= alldevs->next){
        printf("%s\n", alldevs->name);
    }
}
