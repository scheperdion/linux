// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <linux/uhid.h>
#include <linux/major.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <lkl/linux/time.h>
#include <lkl/linux/uhid.h>
#include <dlfcn.h>
#include <arpa/inet.h>


#include <lkl.h>
#include <lkl_host.h>

#include "tcp-fuzzer.h"

// Structure for the IP header
struct ip_header {
    uint8_t  version_ihl;        // Version (4 bits) + Internet Header Length (4 bits)
    uint8_t  tos;                // Type of Service
    uint16_t total_length;       // Total Length (header + data)
    uint16_t identification;     // Identification
    uint16_t flags_fragment_offset; // Flags (3 bits) + Fragment Offset (13 bits)
    uint8_t  ttl;                // Time To Live
    uint8_t  protocol;           // Protocol (e.g., TCP = 6)
    uint16_t header_checksum;    // Header checksum
    uint32_t source_ip;          // Source IP address
    uint32_t dest_ip;            // Destination IP address
} __attribute__((packed));

// Structure for the IGMP header
struct igmp_header {
    uint8_t  type;               // 0x22
    uint8_t  reserved1;
    uint16_t checksum;
    uint16_t reserved2;
} __attribute__((packed));

// Structure for the TCP header
struct tcp_header {
    uint16_t source_port;  // Source port
    uint16_t dest_port;    // Destination port
    uint32_t seq_number;   // Sequence number
    uint32_t ack_number;   // Acknowledgment number
    uint8_t data_offset;   // Data offset + Reserved bits
    uint8_t flags;         // Flags (URG, ACK, PSH, RST, SYN, FIN)
    uint16_t window_size;  // Window size
    uint16_t checksum;     // Checksum
    uint16_t urgent_pointer; // Urgent pointer
} __attribute__((packed));

// Pseudo header needed for TCP checksum calculation
struct pseudo_header {
    uint32_t src_addr;
    uint32_t dest_addr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

// Checksum calculation function
unsigned short tcp_checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Print the TCP header pointed to by tcp for debugging
void print_tcp_ascii(const struct tcp_header *tcp) {
	uint16_t src_port = ntohs(tcp->source_port);
	uint16_t dst_port = ntohs(tcp->dest_port);
	uint32_t seq = ntohl(tcp->seq_number);
	uint32_t ack = ntohl(tcp->ack_number);
	uint8_t data_offset = tcp->data_offset >> 4;
	uint8_t flags = tcp->flags;
	uint16_t win = ntohs(tcp->window_size);
	uint16_t chksum = ntohs(tcp->checksum);
	uint16_t urg = ntohs(tcp->urgent_pointer);

	printf("+-----------------------------+-----------------------------+\n");
	printf("|      Source Port: %5u     |     Dest Port: %5u      |\n", src_port, dst_port);
	printf("+-----------------------------+-----------------------------+\n");
	printf("|                 Sequence Number: %10u              |\n", seq);
	printf("+-----------------------------------------------------------+\n");
	printf("|             Acknowledgment Number: %10u          |\n", ack);
	printf("+------+--------+--------------------------------------------+\n");
	printf("| Data |  Resvd | Flags |     Window Size: %5u           |\n", win);
	printf("| Off  | (0x%01x)   | ", data_offset & 0x0F);
	printf("%c%c%c%c%c%c |\n",
		(flags & 0x20) ? 'U' : '-',
		(flags & 0x10) ? 'A' : '-',
		(flags & 0x08) ? 'P' : '-',
		(flags & 0x04) ? 'R' : '-',
		(flags & 0x02) ? 'S' : '-',
		(flags & 0x01) ? 'F' : '-'
	);
	printf("+-----------------------------+-----------------------------+\n");
	printf("|      Checksum: 0x%04x     |   Urgent Pointer: %5u    |\n", chksum, urg);
	printf("+-----------------------------+-----------------------------+\n");
}
/*
 * 'Create' a 'valid' IGMP packet
 */
void igmp_fix_packet(struct igmp_header *igmp, size_t length) {
	igmp->checksum = 0;
	igmp->checksum = tcp_checksum(igmp, length);
}
/*
 * 'Create' a 'valid' IP packet
 */
int ip_fix_packet(struct ip_header *ip, size_t length) {
	ip->version_ihl = (4 << 4) | 5;
	ip->tos = 0;
	ip->total_length = htons(length);
	//ip->identification = htons(rand() & 0xFFFF); // random identification?
	//ip->flags_fragment_offset = htons(0x4000); // Don't Fragment
	ip->ttl = 64;
	//ip->protocol = 2; // TCP
	ip->header_checksum = 0; // fill in later
	ip->source_ip = inet_addr("127.0.0.1");
	ip->dest_ip = inet_addr("127.0.0.1");
	ip->header_checksum = tcp_checksum(ip, ip->version_ihl & 0x0F);
	return (ip->version_ihl & 0x0F) * 4;
}

int ip_get_protocol(struct ip_header *ip) {
	return ip->protocol;
}

/*
 * 'Create' a 'valid' packet from a stream of bytes (tcp_header)
 */
void tcp_fix_packet(struct tcp_header * tcp_header, size_t length, unsigned int ack_number[], int syn_number) {
	struct pseudo_header psh;
	//tcp_header->source_port = htons(12345);   // Source port
    tcp_header->dest_port = htons(9999);      // Destination port
//    if(syn_number != 0) {
//		tcp_header->seq_number = htonl(syn_number + 1);
//    }
    if(ack_number != 0) {
		tcp_header->ack_number = htonl(ack_number[ntohs(tcp_header->source_port)] + 1);
    }
    int l = length > 60 ? 60 : length;                       // maximum size of tcp header (includes options)
    tcp_header->data_offset = ((l / 4) << 4);                // start of data (end of tcp header)
    //tcp_header->flags = 0x02;
    //tcp_header->window_size = htons(5840);    // Window size
    tcp_header->checksum = 0;               // Initial checksum
    //tcp_header->urgent_pointer = 0;             // Urgent pointer

    // Pseudo header for TCP checksum
    psh.src_addr = inet_addr("127.0.0.1");
    psh.dest_addr = inet_addr("127.0.0.1");
    psh.placeholder = 0;
    psh.protocol = LKL_IPPROTO_TCP;
    psh.tcp_length = htons(length);

    // Calculate TCP checksum
    char pseudogram[sizeof(struct pseudo_header) + length];
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp_header, length);
    tcp_header->checksum = tcp_checksum(pseudogram, sizeof(pseudogram));
}

void hexdump(const char *data, int length) {
    int i;
    for (i = 0; i < length; i += 16) {
        printf("%08x  ", i);

        // Print hex bytes
        for (int j = 0; j < 16; ++j) {
            if (i + j < length)
                printf("%02x ", (unsigned char)data[i + j]);
            else
                printf("   ");
            if (j == 7) printf(" "); // extra space in middle
        }

        printf(" |");

        // Print ASCII characters
        for (int j = 0; j < 16 && i + j < length; ++j) {
            char c = data[i + j];
            printf("%c", isprint((unsigned char)c) ? c : '.');
        }

        printf("|\n");
    }
}

// Constants
#define BUF_SIZE 8192
#define MAX_STATES 12

// Global state counter
int state_counts[MAX_STATES + 1] = {0};

// Optional state name array (not used but kept for reference)
const char *tcp_state_names[MAX_STATES + 1] = {
    "UNKNOWN",      // 0
    "ESTABLISHED",  // 1
    "SYN_SENT",     // 2
    "SYN_RECV",     // 3
    "FIN_WAIT1",    // 4
    "FIN_WAIT2",    // 5
    "TIME_WAIT",    // 6
    "CLOSE",        // 7
    "CLOSE_WAIT",   // 8
    "LAST_ACK",     // 9
    "LISTEN",       // 10
    "CLOSING"       // 11
};

// Convert 2-char hex string to integer (e.g., "0A" => 10)
int parse_state(const char *line) {
    char h1 = line[34], h2 = line[35]; //   0: 3500007F:0035 00000000:0000

    int hi = (h1 >= 'A') ? ((h1 & ~0x20) - 'A' + 10) : (h1 - '0');
    int lo = (h2 >= 'A') ? ((h2 & ~0x20) - 'A' + 10) : (h2 - '0');

    if (hi < 0 || hi > 15 || lo < 0 || lo > 15) return 0;
    return (hi << 4) | lo;
}

void read_tcp_state() {
	int proc_tcp = lkl_sys_open("/proc/net/tcp", LKL_O_RDONLY, 0);
	if (proc_tcp < 0) { printf("lkl_sys_open error\n"); exit(1); }
	int state_counts_local[MAX_STATES + 1] = {0};
	char buf[8192];
	long total = 0;
	long length = 0;
	int header_skip = 0;
    while ((length = lkl_sys_read(proc_tcp, buf, 8192))) {
        for (int i = 0; i < length; ++i) {
            char c = buf[i];
            if (c == '\n') {
                if (header_skip && i+40 < length) {
                    int state = parse_state(&buf[i+1]);
                    if (state >= 0 && state <= MAX_STATES)
                        state_counts_local[state]++;
                    else
                        exit(1);
                } else {
                    header_skip = 1;  // skip header
                }
            }
        }
    }
    for (int i = 0; i < MAX_STATES; ++i) {
	    if(state_counts_local[i] > state_counts[i]) {
		   state_counts[i] = state_counts_local[i];
		}
    }
	lkl_sys_close(proc_tcp);
}

void* terminate_connection(void* arg) {
	// https://blog.cloudflare.com/this-is-strictly-a-violation-of-the-tcp-specification/
	int client_sock = *(int*)arg;
	usleep(50);
	char buf[4096] = {0};
	int len = lkl_sys_recv(client_sock, buf, 4096, MSG_DONTWAIT);
	if (len > 0) {
	    // Data is available
	    printf("Received %d bytes\n", len);
	    hexdump(buf, len);
	}
	else if (len == 0) {
		printf("FIN received!\n");
	}
	else if( len == -ECONNRESET){
        printf("RST received!\n");
	}
	else if (len != -EAGAIN) {
		lkl_perror("Error receiving data", len);
	}
	lkl_sys_close(client_sock);
	return NULL;
}

int generate_tcp_server_socket() {
	int sock, ret;
	struct lkl_sockaddr_in address;
	address.sin_family = LKL_AF_INET;
	address.sin_addr.lkl_s_addr = inet_addr("127.0.0.1");
	address.sin_port = htons(9999);

	// open tcp socket
	sock = lkl_sys_socket(LKL_AF_INET, LKL_SOCK_STREAM, 0);
	if (sock < 0) { printf("lkl_sys_socket error\n"); exit(1); }
	int optval = 1;
	// re-use address (open and close socket more than 10,000 times/second)
	ret = lkl_sys_setsockopt(sock, LKL_SOL_SOCKET, LKL_SO_REUSEADDR, &optval, sizeof(optval));
	if (ret < 0) { printf("lkl_sys_setsockopt error\n"); exit(1); }
	// bind to port
	ret = lkl_sys_bind(sock, (struct lkl_sockaddr *)&address, sizeof(address));
	if (ret < 0) { printf("lkl_sys_bind error\n"); exit(1); }
	// listen
	ret = lkl_sys_listen(sock, 3);
	if (ret < 0) { printf("lkl_sys_listen error\n"); exit(1); }
	// set the socket to non blocking (i.e. recv doesn't block)
	int flags = lkl_sys_fcntl(sock, LKL_F_GETFL, 0);
	ret = lkl_sys_fcntl(sock, LKL_F_SETFL, flags | LKL_O_NONBLOCK);
	if (ret < 0) { printf("lkl_sys_fcntl error\n"); exit(1); }
	return sock;
}

size_t getpacket_length(unsigned char *buf, size_t length) {
	size_t len = 40 + (buf[0] & 0xff);
	if(len > length - 1) len = length - 1;
	return len;
}

void fuzz_tcp_packets(unsigned char* packets, size_t length) {
	// start TCP listener
	int server_sock = generate_tcp_server_socket();
	int clients_size = 0, clients_max = 65535;
	pthread_t clients[65535];

	int ret = 0;
	struct lkl_sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;  // IPv4
    server_addr.sin_addr.lkl_s_addr = inet_addr("127.0.0.1");

    int clientsock = lkl_sys_socket(LKL_AF_INET, LKL_SOCK_RAW, LKL_IPPROTO_TCP); // IPPROTO_RAW is raw ip
	if (clientsock < 0) {
		printf("socket error (%s)\n", lkl_strerror(clientsock));
	}
	int one = 1;
	lkl_sys_setsockopt(clientsock, LKL_IPPROTO_IP, LKL_IP_HDRINCL, &one, sizeof(one));

	char send_packet[4096];
	int start = 0;
	unsigned int ACK_NUMBERS[65536] = { 0 };
	unsigned int SYN_NUMBER = 0;

	while(length > 0) {
		// ++++ PREPARE PACKET
		memset(send_packet, 0, 4096);
		int len = getpacket_length(packets, length);
		//printf("%d \t%d\t%d\n", start, length, len); // len = 0x0 often, it then does 2 bytes for one useless packet, maybe minimal 20 bytes otherwise ignore?
		memcpy(send_packet, packets + 1 + start, len);
		length = length - len - 1;
		start = start + len + 1;

		// ++++ SEND PACKET
		if(len < 40) len = 40;  // minimum TCP packet size
		int ip_length = ip_fix_packet((struct ip_header *)send_packet, len);
		int ip_protocol = ip_get_protocol((struct ip_header *)send_packet);
		if(ip_protocol == 6) {
			tcp_fix_packet((struct tcp_header *)(send_packet + ip_length), len - ip_length, ACK_NUMBERS, SYN_NUMBER);
			memcpy(&SYN_NUMBER, send_packet + ip_length + 4, 4);
			SYN_NUMBER = ntohl(SYN_NUMBER);
		}
		if(ip_protocol == 2) {
			igmp_fix_packet((struct igmp_header *)(send_packet + ip_length), len - ip_length);
		}

		//printf("--- SEND ---\n");
		//print_tcp_ascii((struct tcp_header *)(send_packet + ip_length));
		ret = lkl_sys_sendto(clientsock, send_packet, len, 0, (struct lkl_sockaddr *)&server_addr, sizeof(server_addr));
		if (ret < 0) {
			printf("sendto error (%s)\n", lkl_strerror(ret));
		}

		// ++++ RECEIVE ALL PACKETS CURRENTLY SENT (GIVE TIME TO PROCESS)
		int errors = 0;
		unsigned char recv_packet[1024];
		memset(recv_packet, 0, 1024);
		while(errors == 0) {
			memset(recv_packet, 0, 1024);
			ret = lkl_sys_recv(clientsock, recv_packet, sizeof(recv_packet), LKL_MSG_DONTWAIT);
			if (ret < 0) {
				//printf("recv error (%s)\n", lkl_strerror(ret));
				errors++;
			} else {
				uint16_t src_port = ntohs(((struct tcp_header *) (recv_packet + 20))->source_port);
				uint16_t dst_port = ntohs(((struct tcp_header *) (recv_packet + 20))->dest_port);
				uint32_t seq = ntohl(((struct tcp_header *) (recv_packet + 20))->seq_number);
				if(src_port == 9999) { // if packet was received from listener
					ACK_NUMBERS[dst_port] = seq;  // set ack number to use next time
					//printf("--- RECV ---\n");
					//print_tcp_ascii((struct tcp_header *) (recv_packet + 20));
				}
			}
		}

		// ++++ ACCEPT CONNECTIONS (we are non-blocking so this is OK)
		struct lkl_sockaddr_in client_addr;
		int addr_size = sizeof(client_addr);
		ret = lkl_sys_accept(server_sock, &client_addr, &addr_size);
		if(ret > 0 && clients_size < clients_max) {
			printf("+++ Connection established! (port:%d)\n", ntohs(client_addr.sin_port));
			if (pthread_create(&clients[clients_size], NULL, terminate_connection, &ret) != 0) {
				printf("pthread_create %d\n", ret); exit(1);
			}
			clients_size++;
		} //

		// ++++ READ ALL THE CURRENT TCP STATES FOR COVERAGE GUIDANCE
		//read_tcp_state(); // TODO: this has big performance hit and is only necessary to showcase the fuzzer!
	}


	// close my raw socket
	lkl_sys_close(clientsock);
	// close open sockets
	for(int i = 0; i < clients_size; i++) {
		pthread_join(clients[i], NULL);
	}
	clients_size = 0;
	// close listening socket
	ret = lkl_sys_close(server_sock);
	if(ret < 0) { printf("server socket close fail\n"); exit(1); }
	//printf("DONE\n\n");
}

static int initialize_lkl(void)
{
	int ret = lkl_init(&lkl_host_ops);
	if (ret) {
		printf("lkl_init failed\n");
		return -1;
	}

	ret = lkl_start_kernel("mem=50M kasan.fault=panic loglevel=2");
	if (ret) {
		printf("lkl_start_kernel failed\n");
		lkl_cleanup();
		return -1;
	}

	lkl_mount_fs("proc");
	lkl_if_up(1);                   // to enable loopback interface
//	pthread_t thread_id;            // to start the TCP server listiner inside LKL
//	if (pthread_create(&thread_id, NULL, initialize_tcp_server, NULL) != 0) {
//		perror("pthread_create");
//	}
//	sleep(1);
	return 0;
}



void flush_coverage(void)
{
	__llvm_profile_write_file();
}

void end_fuzzing(void) {
	flush_coverage();
	//lkl_sys_halt(); TODO: temporary comment, my kernel is built with options where the UndefinedBehavior sanitizer error shows up
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	initialize_lkl();
	__llvm_profile_initialize_file();
	atexit(end_fuzzing);

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	static int iter;
	uint8_t data[65535] = {0};

	if (Size > 65535)
		Size = 65535;

	memcpy(data, Data, Size);
	fuzz_tcp_packets(data, Size);
	iter++;
	if (iter > 1000) {
		flush_coverage();
		iter = 0;
//		for (int i = 0; i <= MAX_STATES; ++i) {
//            char msg[64];
//            printf("%-12s : %d\n", tcp_state_names[i], state_counts[i]);
//    	}
	}
	return 0;
}