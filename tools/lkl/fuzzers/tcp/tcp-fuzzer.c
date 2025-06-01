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
};

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
 * 'Create' a 'valid' packet from a stream of bytes (tcp_header)
 */
void tcp_fix_packet(struct tcp_header * tcp_header, size_t length, int ack_number, int syn_number) {
	struct pseudo_header psh;
	//tcp_header->source_port = htons(12345);   // Source port
    tcp_header->dest_port = htons(9999);      // Destination port
//    if(syn_number != 0) {
//		tcp_header->seq_number = htonl(syn_number + 1);
//    }
    if(ack_number != 0) {
		tcp_header->ack_number = htonl(ack_number + 1);
    }
    int l = length > 60 ? 60 : length;                       // maximum size of tcp header
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

void* initialize_tcp_server(void* arg) {
	int sock;
	struct lkl_sockaddr_in address;
	address.sin_family = LKL_AF_INET;
	address.sin_addr.lkl_s_addr = inet_addr("127.0.0.1");
	address.sin_port = htons(9999);

	sock = lkl_sys_socket(LKL_AF_INET, LKL_SOCK_STREAM, 0);
	lkl_sys_bind(sock, (struct lkl_sockaddr *)&address, sizeof(address));
	lkl_sys_listen(sock, 3);

	struct lkl_sockaddr client_addr;
	int addr_size = sizeof(client_addr);
	//int value = *(int*)arg;
	printf("Waiting for connection...\n");
	while(true) {
		int ret = lkl_sys_accept(sock, &client_addr, &addr_size);
		if(ret < 0) { printf("--- FAIL %d\n", ret); }
		else { printf("+++ Connection established!\n"); sleep(1); lkl_sys_close(ret); } //
	}
//	exit(EXIT_SUCCESS);
	return 0;
}

size_t getpacket_length(unsigned char *buf, size_t length) {
	size_t len = 20 + (buf[0] & 0xff);
	if(len > length - 1) len = length - 1;
	return len;
}

void fuzz_tcp_packets(unsigned char* packets, size_t length) {
	int ret = 0;
	struct lkl_sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;  // IPv4
    server_addr.sin_addr.lkl_s_addr = inet_addr("127.0.0.1");

    int clientsock = lkl_sys_socket(LKL_AF_INET, LKL_SOCK_RAW, LKL_IPPROTO_TCP); // IPPROTO_RAW is raw ip
	if (clientsock < 0) {
		printf("socket error (%s)\n", lkl_strerror(clientsock));
	}
	char send_packet[1024];
	int start = 0;
	unsigned int ACK_NUMBER = 0;
	unsigned int SYN_NUMBER = 0;
	while(length > 0) {
		// prepare packet
		memset(send_packet, 0, 1024);
		int len = getpacket_length(packets, length);
		//printf("%d \t%d\t%d\n", start, length, len); // len = 0x0 often, it then does 2 bytes for one useless packet, maybe minimal 20 bytes otherwise ignore?
		memcpy(send_packet, packets + 1 + start, len);
		length = length - len - 1;
		start = start + len + 1;

		// send packet
		if(len < 20) len = 20;  // minimum TCP packet size
		tcp_fix_packet((struct tcp_header *)send_packet, len, ACK_NUMBER, SYN_NUMBER);
		memcpy(&SYN_NUMBER, send_packet + 4, 4);
		SYN_NUMBER = ntohl(SYN_NUMBER);
		//printf("--- SEND ---\n");
		//print_tcp_ascii((struct tcp_header *)send_packet);
		ret = lkl_sys_sendto(clientsock, send_packet, len, 0, (struct lkl_sockaddr *)&server_addr, sizeof(server_addr));
		if (ret < 0) {
			printf("sendto error (%s)\n", lkl_strerror(ret));
		}

		int errors = 0;
		unsigned char recv_packet[1024];
		memset(recv_packet, 0, 1024);
		while(errors == 0) { // receive all packets before terminating fuzzing input
			memset(recv_packet, 0, 1024);
			ret = lkl_sys_recv(clientsock, recv_packet, sizeof(recv_packet), LKL_MSG_DONTWAIT);
			if (ret < 0) {
				//printf("recv error (%s)\n", lkl_strerror(ret));
				errors++;
			} else {
				uint16_t src_port = ntohs(((struct tcp_header *) (recv_packet + 20))->source_port);
				uint32_t seq = ntohl(((struct tcp_header *) (recv_packet + 20))->seq_number);
				if(src_port == 9999) { // if packet was received from listener
					ACK_NUMBER = seq;  // set ack number to use next time
					//printf("--- RECV ---\n");
					//print_tcp_ascii((struct tcp_header *) (recv_packet + 20));
				}
			}
		}
	}
	//printf("DONE\n\n");
	lkl_sys_close(clientsock);
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

	lkl_if_up(1);                   // to enable loopback interface
	pthread_t thread_id;            // to start the TCP server listiner inside LKL
	if (pthread_create(&thread_id, NULL, initialize_tcp_server, NULL) != 0) {
		perror("pthread_create");
	}
	sleep(1);
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
	}
	return 0;
}