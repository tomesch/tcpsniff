#include "tcpsniff.h"

int main(int argc, char *argv[]){
	char * iflag;
	char * oflag;
	char * fflag;
	int vflag, pflag=0;
	int c;

	while ((c = getopt (argc, argv, "i:o:f:v:p")) != -1){
		switch(c){
			case 'p' :
				pflag = 1;
				break;
			case 'i' :
				iflag = strdup(optarg);
				break;
			case 'o' :
				oflag = strdup(optarg);
				break;
			case 'f' :
				fflag = strdup(optarg);
				break;
			case 'v' :
				vflag = atoi(optarg);
				break;
			default:
				break;
		}
	}

	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t * capture_handle;

	if((capture_handle = pcap_create(iflag, error_buffer))==NULL){
		fprintf(stderr,"Error in pcap_create: %s\n", error_buffer);
		exit(1);
	}

	pcap_set_snaplen(capture_handle,65535);
	if(pflag==1){
		pcap_set_promisc(capture_handle, 1);
	}

	if((pcap_activate(capture_handle) == PCAP_ERROR_NO_SUCH_DEVICE)){
		printf("Device (%s) does not exist\n",iflag);
		printf("Please use one of the following devices : \n");
		print_all_devices();
	}

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
void print_header_tcp(const u_char *packet){
	printf("|---> TCP ");
	struct tcphdr *tcp;
	tcp = (struct tcphdr*)packet;
	printf("%d > %d\n",ntohs(tcp->source), ntohs(tcp->dest));
	
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


void print_header_udp(const u_char *packet){
	printf("|---> UDP ");
	struct udphdr *udp;
	udp = (struct udphdr*)packet;
	printf("%d > %d\n",ntohs(udp->source),ntohs(udp->dest));
}

void print_header_ip(const u_char *packet){
	struct ip *ip_header; 
	ip_header = (struct ip*)packet;
	char src[INET_ADDRSTRLEN];
	char dst[INET_ADDRSTRLEN];
	int version = ip_header->ip_v;
	inet_ntop(AF_INET,&(ip_header->ip_src),src,INET_ADDRSTRLEN);
	inet_ntop(AF_INET,&(ip_header->ip_dst),dst,INET_ADDRSTRLEN);
	printf("|--> IPv%d %s > %s \n",version,src,dst);

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
	printf("|--> ARP \n");
}

char * uintip_to_string(uint32_t ip){
	uint8_t  octet[4];
	char *res = malloc(15*sizeof(int));
	int x;
	for (x = 0; x < 4; x++){
		octet[x] = (ip >> (x * 8)) & (uint8_t)-1;
	}
	sprintf(res,"%d.%d.%d.%d",octet[0],octet[1],octet[2],octet[3]);
	return res;	
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
