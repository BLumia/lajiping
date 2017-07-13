#include <stdio.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "lajiping.h"

byte packet_need_send[PACKET_SIZE];
byte packet_received[PACKET_SIZE];
int sockfd, datalen = 56;
int nsend = 0, nreceived = 0;
struct sockaddr_in dest_addr; // destination address info
struct sockaddr_in from; // sender / localhost address info
struct timeval tvrecv; 
pid_t pid; 
int options; 
char *hostname = NULL; 
char hnamebuf[MAXHOSTNAMELEN];
char *prgname = NULL; 

char usage[] = 
"usage:%s [-h?drv] [--help] [(hostname/IP address) [count]]\n";

void statistics(int signo) {     
	fflush(stdout);
	printf("\n------------%s PING statistics------------\n", hostname);
	if(nsend > 0)
		printf("%d packets transmitted, %d received , %2.0f%%  lost\n",
				nsend,nreceived,(float)(nsend-nreceived)/nsend*100);
	else
		printf("have problem in send packets!\n");
	
	if(sockfd)
		close(sockfd);
	exit(0);
}

u_int16_t cal_chksum(u_int16_t *addr,int len) {   
	u_int32_t sum = 0;
	u_int16_t *buf = addr;
	u_int16_t result = 0;

	for (sum = 0; len > 1; len -= 2)
		sum += *buf++;
	if (len == 1)
		sum += *(u_int8_t*)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

int mk_icmp_pack(int pack_no) {       
	int packsize;
	struct icmp *icmp;
	struct timeval *tval;

	icmp = (struct icmp*)packet_need_send;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_seq = pack_no;
	icmp->icmp_id = pid;
	packsize = 8 + datalen;
	tval = (struct timeval *)icmp -> icmp_data;
	gettimeofday(tval, NULL); 
	icmp->icmp_cksum = cal_chksum( (u_int16_t *)icmp, packsize); 
	return packsize;
}


int process_received_packet(byte *buf,int len) {       
	int iphdrlen;
	struct ip *ip;
	struct icmp *icmp;
	struct timeval *tvsend;
	double rtt;

	ip = (struct ip *)buf;

	iphdrlen = ip->ip_hl << 2; 
	icmp = (struct icmp *)(buf + iphdrlen); 
	int icmplen = len - iphdrlen; 

	if(icmplen < sizeof(struct icmphdr)) {       
		printf("ICMP packets\'s length is less than icmphdr\n");
		return -1;
	}

	// pid match for check
	if( (icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid) ) {       
		tvsend = (struct timeval *)icmp->icmp_data;
		struct timeval deltatime;
		timersub(&tvrecv,tvsend,&deltatime);
		rtt = deltatime.tv_sec * 1000 + deltatime.tv_usec / 1000; // result in ms
		printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%.3f ms\n",
			icmplen, inet_ntoa(from.sin_addr), icmp->icmp_seq, ip->ip_ttl, rtt);
		if(options & PS_IPDATA) {
			printf("HEX dump of ICMP package:\n");
			//for(int i = 1; i <= icmplen; i++) printf(" %02hhX", ((byte*)icmp)[i - 1]); 
			//putchar('\n');
			hex_dump((char *)icmp, icmplen);
			fflush(stdout);
		} 
	} else {
		return -1;
	}  

	return 0;
}

void send_packet() {
	    
	int packetsize;

	packetsize = mk_icmp_pack(nsend);
	if( sendto(sockfd, packet_need_send, packetsize, 0,
			  (struct sockaddr *)&dest_addr, sizeof(dest_addr) ) < 0  ) {
		perror("sendto error");
	}
	nsend++;
	// sleep after recv
}

void recv_packet() { 
	
	unsigned int n,fromlen;
	extern int errno;

	signal(SIGALRM, statistics);
	fromlen = sizeof(from);
	while(nreceived < nsend) {       

		//alarm(MAX_WAIT_TIME);
		if( (n=recvfrom(sockfd, packet_received, sizeof(packet_received), 0,
						(struct sockaddr *)&from, &fromlen)) < 0) {
			if(errno == EINTR)   
				continue;
			perror("recvfrom error");
			continue;
		}

		gettimeofday(&tvrecv, NULL); 
		if(process_received_packet(packet_received, n) == -1)
			continue;
		nreceived++;
		sleep(1);
	}

}

// not using getopt() since special ip argument
int process_arguments(int *argc, char **argv) {

	char **av = argv;
	int count = *argc;

	(*argc)--, av++;
	while((*argc > 0) && ('-' == *av[0])) {
		if('-' == *(av[0]+1)) {
			char *temp = av[0];
			if(!strcmp(temp + 2, "help")) {
				printf(usage, prgname);
				exit(0);
			} else {
				printf("Bad arguments in command line!\n");
				printf(usage, prgname);
				exit(1);
			} 
		}
		// for case of '-a' or '-ax', 
		// every letter treat as a option 
		while(*++av[0]) switch(*av[0]) {
				case 'h':
				case '?':
					printf(usage, prgname);
					exit(0);
				case 'd':
					options |= SO_DEBUG;
					break;
				case 'r':
					options |= SO_DONTROUTE;
					break;
				case 'v':
					options |= PS_IPDATA;
					break;
				default:
					fprintf(stderr, "Bad arguments in command line. \n");
					exit(1);
		}
		(*argc)--, av++;
	}

	return (count - *argc);
}

void hex_dump(const char *buf, int len) {
	const char* addr = buf;
    int i,j,k;
    char binstr[80];
 
    for (i=0;i<len;i++) {
        if (0==(i%16)) {
            sprintf(binstr,"%08x -",i+addr);
            sprintf(binstr,"%s %02x",binstr,(byte)buf[i]);
        } else if (15==(i%16)) {
            sprintf(binstr,"%s %02x",binstr,(byte)buf[i]);
            sprintf(binstr,"%s  ",binstr);
            for (j=i-15;j<=i;j++) {
                sprintf(binstr,"%s%c",binstr,('!'<buf[j]&&buf[j]<='~')?buf[j]:'.');
            }
            printf("%s\n",binstr);
        } else {
            sprintf(binstr,"%s %02x",binstr,(byte)buf[i]);
        }
    }
    if (0!=(i%16)) {
        k=16-(i%16);
        for (j=0;j<k;j++) {
            sprintf(binstr,"%s   ",binstr);
        }
        sprintf(binstr,"%s  ",binstr);
        k=16-k;
        for (j=i-k;j<i;j++) {
            sprintf(binstr,"%s%c",binstr,('!'<buf[j]&&buf[j]<='~')?buf[j]:'.');
        }
        printf("%s\n",binstr);
    }
}
 
int main(int argc,char *argv[]) {  

	struct hostent *host; 
	struct protoent *protocol;
	unsigned long inaddr=0l;
	//int waittime = MAX_WAIT_TIME;    //#define MAX_WAIT_TIME   5
	int size = 50 * 1024;
	int cmd_line_opts_start = 1;
	unsigned int pgcount = 0;
	int on = 1;

	prgname = strrchr(argv[0], '/');
	if(prgname) prgname++;
	else prgname = argv[0];

	cmd_line_opts_start = process_arguments(&argc, argv);

	if(argc < 1 || argc > 2) {       
		printf(usage, prgname);
		exit(1);
	}
	
	if(1 == argc) {
		hostname = argv[cmd_line_opts_start];
	} else {
		hostname = argv[cmd_line_opts_start];
		pgcount = (unsigned int)strtol(argv[++cmd_line_opts_start], NULL, 10);
	}

	if((protocol = getprotobyname("icmp")) == NULL) {       
		perror("getprotobyname");
		exit(1);
	}

	// need root / administator
	if((sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto))<0) {       
		perror("socket error");
		exit(1);
	}

	setuid(getuid());

	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size) );
	if(options & SO_DEBUG) {
		printf(".....debug on.....\n");
		setsockopt(sockfd, SOL_SOCKET, SO_DEBUG, &on, sizeof(on));
	}

	if(options & SO_DONTROUTE) {
		setsockopt(sockfd, SOL_SOCKET, SO_DONTROUTE, &on, sizeof(on));
	}

	bzero(&dest_addr, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET; // ipv4 socket

	//inet_addr: Converts the Internet host address cp from IPv4 numbers-and-dots notation into binary data in network byte order. If the input is invalid, INADDR_NONE (usually -1) is returned.
	if((inaddr = inet_addr(hostname)) == INADDR_NONE) {
		// host name / domain
		if((host = gethostbyname(hostname)) == NULL) {       
			perror("gethostbyname error");
			exit(1);
		}
		memcpy((char *)&dest_addr.sin_addr, host->h_addr, host->h_length);
		strncpy(hnamebuf, host->h_name, MAXHOSTNAMELEN-1);
		hostname = hnamebuf;
	} else { 
		// IP addr	
		dest_addr.sin_addr.s_addr = inet_addr(hostname);
	}

	pid = getpid(); // for icmp_id , any value is okay 
	printf("PING %s(%s): %d bytes data in ICMP packets.\n",hostname,
					inet_ntoa(dest_addr.sin_addr),datalen);
	signal(SIGINT, statistics);
	signal(SIGALRM, statistics);

	for(;;) {
		send_packet();  
		recv_packet(); 

		if(pgcount && nreceived >= pgcount)
			statistics(SIGALRM);
	}

	// never run at here, end at statistics() !
	if(sockfd)
		close(sockfd);

	return 0;
}
