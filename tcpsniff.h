#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>
#include <time.h>
#include <netinet/if_ether.h>

int main(int argc, char *argv[]);
void got_packet(u_char *user, const struct pcap_pkthdr *phrd, const u_char *pdata);
void print_all_devices();