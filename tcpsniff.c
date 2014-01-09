#include "tcpsniff.h"

int vflag = 1;

int main(int argc, char *argv[]){
	char * iflag=NULL;
	char * oflag=NULL;
	char * fflag=NULL;
	int pflag=0;
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

		printf("listening on %s, capture size %d bytes\n",iflag,CAPTURESIZE);
	}
	else{ // offline mode
		if((capture_handle = pcap_open_offline(oflag,error_buffer))==NULL){
			fprintf(stderr,"%s\n",error_buffer);
			exit(1);
		}	
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

	// start receiving packets
	if((pcap_loop(capture_handle, 0, (pcap_handler)got_packet, NULL))==-1){
		char *prefix = "Error in pcap_loop";
		pcap_perror(capture_handle, prefix);
		printf("Error in loop\n");
	}

	pcap_close(capture_handle);
	return 0;
}

void print_header_telnet(const u_char *packet,int length){
	if(vflag==1){
        printf("TELNET");
    }
    if(vflag==2){
        printf("|----> TELNET\n"); 
    }
    if(vflag==3){
        printf("|----> TELNET\n");
        struct tcphdr *tcp = (struct tcphdr*) packet;
        print_ascii((u_char *)packet+(4*tcp->doff),length-4*tcp->doff-sizeof(struct ip));
        printf("\n");
    }
}
void print_header_http(const u_char *packet,int length){
	if(vflag==1){
        printf("HTTP");
    }
    if(vflag==2){
        printf("|----> HTTP\n"); 
    }
    if(vflag==3){
        printf("|----> HTTP\n");
        struct tcphdr *tcp = (struct tcphdr*) packet;
        print_ascii((u_char *)packet+(4*tcp->doff),length-4*tcp->doff-sizeof(struct ip));
        printf("\n");
    }
}
void print_header_https(const u_char *packet,int length){
	if(vflag==1){
        printf("HTTPS");
    }
    else{    
        printf("|----> HTTPS\n");
    }
}
void print_header_ftp(const u_char *packet,int length){
   	if(vflag==1){
        printf("FTP");
    }
    if(vflag==2){
        printf("|----> FTP\n"); 
    }
    if(vflag==3){
        printf("|----> FTP\n");
        struct tcphdr *tcp = (struct tcphdr*) packet;
        print_ascii((u_char *)packet+(4*tcp->doff),length-4*tcp->doff-sizeof(struct ip));
        printf("\n");
    }
}
void print_header_pop(const u_char *packet,int length){
   	if(vflag==1){
        printf("POP");
    }
    if(vflag==2){
        printf("|----> POP\n"); 
    }
    if(vflag==3){
        printf("|----> POP\n");
        struct tcphdr *tcp = (struct tcphdr*) packet;
        print_ascii((u_char *)packet+(4*tcp->doff),length-4*tcp->doff-sizeof(struct ip));
        printf("\n");
    }
}
void print_header_imap(const u_char *packet,int length){
   	if(vflag==1){
        printf("IMAP");
    }
    if(vflag==2){
        printf("|----> IMAP\n"); 
    }
    if(vflag==3){
        printf("|----> IMAP\n");
        struct tcphdr *tcp = (struct tcphdr*) packet;
        print_ascii((u_char *)packet+(4*tcp->doff),length-4*tcp->doff-sizeof(struct ip));
        printf("\n");
    }
}
void print_header_smtp(const u_char *packet,int length){
    if(vflag==1){
        printf("SMTP");
    }
    if(vflag==2){
        printf("|----> SMTP\n"); 
    }
    if(vflag==3){
        printf("|----> SMTP\n");
        struct tcphdr *tcp = (struct tcphdr*) packet;
        print_ascii((u_char *)packet+(4*tcp->doff),length-4*tcp->doff-sizeof(struct ip));
        printf("\n");
    }
}
void get_flags_tcp(struct tcphdr *tcp, char **flags){
	char *  str = malloc(100*sizeof(char));
	str[0] = '\0';
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
void print_header_tcp(const u_char *packet,int length){
	struct tcphdr *tcp;
	tcp = (struct tcphdr*)packet;
	char * flags;
	get_flags_tcp(tcp,&flags);

	if(vflag==1){
		printf("TCP %d > %d | ",ntohs(tcp->source), ntohs(tcp->dest));
	}
	if(vflag==2){	
		printf("|---> TCP %d > %d, Flags: [%s] \n",ntohs(tcp->source), ntohs(tcp->dest),flags);
	}
	if(vflag==3){
		printf("|---> TCP %d > %d, Flags: [%s], Seq number: %u, Ack number: %u , Window size: %d, Checksum: 0x%x\n",ntohs(tcp->source), ntohs(tcp->dest),flags,ntohl(tcp->seq),ntohl(tcp->ack_seq),ntohs(tcp->window),ntohs(tcp->check));
	}

	switch(ntohs(tcp->source)){
		case HTTPPORT:
			print_header_http(packet,length);
			break;
		case HTTPSPORT:
			print_header_https(packet,length);
			break;
		case FTPDATAPORT:
			print_header_ftp(packet,length);
			break;
		case FTPCONTROLPORT:
			print_header_ftp(packet,length);
			break;
		case TELNETPORT:
			print_header_telnet(packet,length);
			break;
		case SMTPPORT:
			print_header_smtp(packet,length);
			break;
        case POPPORT:
			print_header_pop(packet,length);
			break;
        case IMAPPORT:
			print_header_imap(packet,length);
			break;
        default:
			switch(ntohs(tcp->dest)){	
				case HTTPPORT:
					print_header_http(packet,length);
					break;
				case HTTPSPORT:
					print_header_https(packet,length);
					break;
				case FTPDATAPORT:
					print_header_ftp(packet,length);
					break;
				case FTPCONTROLPORT:
					print_header_ftp(packet,length);
					break;
				case TELNETPORT:
					print_header_telnet(packet,length);
					break;
				case SMTPPORT:
					print_header_smtp(packet,length);
					break;	
                 case POPPORT:
			        print_header_pop(packet,length);
			        break;
                 case IMAPPORT:
			        print_header_imap(packet,length);
			        break; 
				default:
                    if(vflag==1){
                        printf("Unknown %d > %d",ntohs(tcp->source),ntohs(tcp->dest));
                    }
                    else{
                        printf("|----> Unknown %d > %d\n",ntohs(tcp->source),ntohs(tcp->dest));
                    }
					break;
			}
	}
}
void print_ascii(u_char *packet, int length){
	int i;
	int rank = 0;
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
		else{
			printf(".");
        }
		if(rank%64==63){
			printf("\n");
        }
	}
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
					strncpy(buffer,(const char *)&bootp->bp_vend[i+2],bootp->bp_vend[i+1]);
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

    if(vflag==1){
        printf("BOOTP");
        if(dhcp_type!=NULL){
            printf(" DHCP %s",dhcp_type);
        }
    }
    else{
        printf("|----> BOOTP Client IP: %s, Your IP: %s, Server IP: %s, Gateway IP: %s\n",inet_ntoa(bootp->bp_ciaddr),inet_ntoa(bootp->bp_yiaddr),inet_ntoa(bootp->bp_siaddr),inet_ntoa(bootp->bp_giaddr));

        if(dhcp_type!=NULL){
            printf("       DHCP %s\n",dhcp_type);
            if(vflag==3){
                if(strcmp(dhcp_type,"DISCOVER")==0 || strcmp(dhcp_type,"REQUEST")==0){
                    printf("       Parameters: %s\n",dhcp_request);
                }
                if(strcmp(dhcp_type,"OFFER")==0 || strcmp(dhcp_type,"ACK")==0){
                    printf("%s",dhcp_options);		
                }
            }
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
	char * tmp = malloc(100*sizeof(char)); 
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
void print_header_dns(const u_char *packet,int length){
	struct dnshdr *dns;
	dns = (struct dnshdr*) packet;
	char * qr;
	char * opcode;
	char * flags;
	get_flags_dns(dns->flags,&qr,&opcode,&flags);
	if(vflag==1){
		printf("DNS %s (%s)",qr,opcode);
	}
	if(vflag==2){
		printf("|----> DNS %s (%s), Flags: [%s]\n",qr,opcode,flags);
	}
	if(vflag==3){
		printf("|----> DNS %s (%s), Flags: [%s]\n",qr,opcode,flags);
	}	
}

void print_header_udp(const u_char *packet,int length){
	struct udphdr *udp;
	udp = (struct udphdr*)packet;
	if(vflag==1){
		printf("UDP %d > %d | ",ntohs(udp->source),ntohs(udp->dest));
	}
	if(vflag==2){
		printf("|---> UDP %d > %d, Length: %d\n",ntohs(udp->source),ntohs(udp->dest),ntohs(udp->len));
	}
	if(vflag==3){
		printf("|---> UDP %d > %d, Length: %d, Checksum: 0x%x\n",ntohs(udp->source),ntohs(udp->dest),ntohs(udp->len),ntohs(udp->check));
	}
	switch(ntohs(udp->source)){
		case BOOTPSERVERPORT:
			print_header_bootp((packet+sizeof(struct udphdr)));
			break;
		case BOOTPCLIENTPORT:
			print_header_bootp((packet+sizeof(struct udphdr)));
			break;
		case DNSPORT:
			print_header_dns((packet+sizeof(struct udphdr)),length);
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
					print_header_dns((packet+sizeof(struct udphdr)),length);
					break;	
				default:
                    if(vflag==1){
                        printf("Unknown %d > %d",ntohs(udp->source),ntohs(udp->dest));
                    }
                    else{
                        printf("|---> Unknown %d > %d\n",ntohs(udp->source),ntohs(udp->dest));
                    }
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

	if(vflag==1){
		printf("IPv%d %s > %s | ",version,src,dst);
	}
	if(vflag==2){
		printf("|--> IPv%d %s > %s, Length: %d, ID: Ox%x\n",version,src,dst,ip_header->ip_len,ntohs(ip_header->ip_id));
	}
	if(vflag==3){
		printf("|--> IPv%d %s > %s, Length: %d, ID: 0x%x, TTL : %d, Checksum: 0x%x \n",version,src,dst,ntohs(ip_header->ip_len),ntohs(ip_header->ip_id),ip_header->ip_ttl,ntohs(ip_header->ip_sum));
	}

	switch(ip_header->ip_p){
		case 6:
			print_header_tcp((packet+sizeof(struct ip)),ntohs(ip_header->ip_len));
			break;
		case 17:
			print_header_udp((packet+sizeof(struct ip)),ntohs(ip_header->ip_len));
			break;
		default:
			break; 
	}
}

void print_header_arp(const u_char *packet){
	struct arphdr *arp;
	arp = (struct arphdr*) packet;
	char * srcip = malloc(100*sizeof(char));
	char * dstip = malloc(100*sizeof(char));
	char * sha = malloc(100*sizeof(char));
	u_char * addresses = (u_char *) arp + sizeof(struct arphdr);
	
	sprintf(sha,"%02x:%02x:%02x:%02x:%02x:%02x",addresses[0],addresses[1],addresses[2],addresses[3],addresses[4],addresses[5]);	
	sprintf(dstip,"%d.%d.%d.%d",addresses[16],addresses[17],addresses[18],addresses[19]);	
	sprintf(srcip,"%d.%d.%d.%d",addresses[6],addresses[7],addresses[8],addresses[9]);	

	switch(ntohs(arp->ar_op)){
		case ARPOP_REQUEST:
            if(vflag==1){
			    printf("ARP request who has %s ? Tell %s",dstip,srcip);
			}
            else{
                 printf("|--> ARP request who has %s ? Tell %s\n",dstip,srcip);
            }
            break;
		case ARPOP_REPLY:
		    if(vflag==1){
			    printf("ARP reply %s is at %s",srcip,sha);			
            }
            else{
                printf("|--> ARP reply %s is at %s\n",srcip,sha);
            }
			break;
		case ARPOP_RREQUEST:
            if(vflag==1){
			    printf("RARP request");
            }
            else{ 
		        printf("|--> RARP request\n");
            }
			break;
		case ARPOP_RREPLY:
            if(vflag==1){
			    printf("RARP reply");
            }
            else{
			    printf("|--> RARP reply\n");
            }
			break;
		case ARPOP_InREQUEST:
            if(vflag==1){
			    printf("InARP request");
            }
            else{
			    printf("|--> InARP request\n");
            }
			break;
		case ARPOP_InREPLY:
            if(vflag==1){
			    printf("InARP reply");
            }
            else{
			    printf("|--> InARP reply\n");
            }
			break;
		case ARPOP_NAK:
            if(vflag==1){
			    printf("ARP NAK");
            }
            else{
			    printf("|--> ARP NAK\n");
            }
			break;
		default:
			break;
	}
}

char * get_human_time(struct timeval tv){
	struct tm* ptm; 
	char * time_string = malloc(40*sizeof(char));
	char * human_string = malloc(40*sizeof(char)); 
	long milliseconds; 
	gettimeofday (&tv, NULL); 
	ptm = (struct tm*) localtime (&tv.tv_sec); 
	strftime (time_string,40,"%H:%M:%S", ptm); 
	milliseconds = tv.tv_usec; 
	sprintf(human_string,"%s.%06ld", time_string, milliseconds);
	return human_string; 
}

void got_packet(u_char *user, const struct pcap_pkthdr *phrd, const u_char *packet){
	struct ether_header *ethernet; 
	ethernet = (struct ether_header*)packet;
	char * ether_dhost = malloc(20*sizeof(char));
	char * ether_shost = malloc(20*sizeof(char));

	sprintf(ether_shost,"%02x:%02x:%02x:%02x:%02x:%02x",ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);	
	sprintf(ether_dhost,"%02x:%02x:%02x:%02x:%02x:%02x",ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);	
	
	if(vflag==1){
        printf("%s Ethernet %s > %s | ",get_human_time(phrd->ts),ether_shost,ether_dhost);    
    }
    else{
	    printf("%s\n",get_human_time(phrd->ts));
        printf("|-> Ethernet %s > %s\n",ether_shost,ether_dhost);
    }

	switch(ntohs(ethernet->ether_type)){
		case 0x0800:
			print_header_ip((packet+sizeof(struct ether_header)));
			break;
		case 0x0806:
			print_header_arp((packet+sizeof(struct ether_header)));
			break;
		default:
            if(vflag==1){
                printf("Unknown, type: 0x%x",ntohs(ethernet->ether_type));
            }
            else{
                printf("|--> Unknown, type: 0x%x \n",ntohs(ethernet->ether_type));
            }
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
