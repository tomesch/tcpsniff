#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>
#include <time.h>

int main(int argc, char *argv[]);
void got_packet(u_char *user, struct pcap_pkthdr *phrd, u_char *pdata);
void print_all_devices();
char * human_time(struct timeval *ts);