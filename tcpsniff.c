#include "tcpsniff.h"

int main(int argc, char *argv[]){
	// Command line flags
	char * iflag;
	char * oflag;
	char * fflag;
	int vflag, pflag=0;

	// Parsing command line flags
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

	if((pcap_activate(capture_handle) == PCAP_ERROR_NO_SUCH_DEVICE)){
		printf("Device (%s) does not exist\n",iflag);
		printf("Please use one of the following devices : \n");
		print_all_devices();
	}

	pcap_loop(capture_handle, 0, (pcap_handler)got_packet, NULL);
    return 0;
}

void got_packet(u_char *user, struct pcap_pkthdr *phrd, u_char *pdata){
	struct timeval tv = phrd->ts; 
	struct tm* ptm; 
	char time_string[40]; 
	long milliseconds; 
	gettimeofday (&tv, NULL); 
	ptm = (struct tm*) localtime (&tv.tv_sec); 
	strftime (time_string, sizeof (time_string), "%H:%M:%S", ptm); 
	milliseconds = tv.tv_usec; 
	printf ("%s.%03ld\n", time_string, milliseconds); 
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