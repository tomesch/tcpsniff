#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>
#include <time.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "bootp.h"
#define CAPTURESIZE 65535

int main(int argc, char *argv[]);
void got_packet(u_char *user, const struct pcap_pkthdr *phrd, const u_char *pdata);
void print_all_devices();
char * uintip_to_string(uint32_t ip);
