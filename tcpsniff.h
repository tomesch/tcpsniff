#include <string.h>
#include <stdio.h>
#include <ctype.h>
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
#include <arpa/inet.h>

#define CAPTURESIZE 65535

// well known ports
#define IMAPPORT 143
#define POPPORT 110
#define FTPDATAPORT 20
#define FTPCONTROLPORT 21
#define TELNETPORT 23
#define SMTPPORT 25
#define DNSPORT 53
#define BOOTPSERVERPORT 67
#define BOOTPCLIENTPORT 68
#define HTTPPORT 80
#define HTTPSPORT 443

struct dnshdr {
        uint16_t xid;
        uint16_t flags;
        uint16_t qdcount;
        uint16_t ancount;
        uint16_t nscount;
        uint16_t arcount;
};

int main(int argc, char *argv[]);
void print_header_telnet(const u_char *packet,int length);
void print_header_http(const u_char *packet,int length);
void print_header_https(const u_char *packet,int length);
void print_header_ftp(const u_char *packet,int length);
void print_header_pop(const u_char *packet,int length);
void print_header_imap(const u_char *packet,int length);
void print_header_smtp(const u_char *packet,int length);
void get_flags_tcp(struct tcphdr *tcp, char **flags);
void print_header_tcp(const u_char *packet,int length);
void print_ascii(u_char *packet, int length);
void print_header_bootp(const u_char *packet);
void get_flags_dns(uint16_t flags_i, char** qr, char ** opcode, char ** flags);
void print_header_dns(const u_char *packet,int length);
void print_header_udp(const u_char *packet,int length);
void print_header_ip(const u_char *packet);
void print_header_arp(const u_char *packet);
char * get_human_time(struct timeval tv);
void got_packet(u_char *user, const struct pcap_pkthdr *phrd, const u_char *packet);
void print_all_devices();

