typedef unsigned char   byte;

#define PACKET_SIZE     64
#define MAX_WAIT_TIME   5
#define MAX_NO_PACKETS  3
#define PS_IPDATA       0x2000

#ifndef MAXHOSTNAMELEN 
#define MAXHOSTNAMELEN  64
#endif /* MAXHOSTNAMELEN */

#ifdef __CYGWIN__
#define __USE_BSD
#include "ip_icmp.h"
#endif /* __CYGWIN__ */

void statistics(int signo);
u_int16_t cal_chksum(u_int16_t *addr, int len);
int mk_icmp_pack(int pack_no);
int process_received_packet(byte *buf, int len);
void send_packet();
void recv_packet();
void hex_dump(const char *buf, int len);
