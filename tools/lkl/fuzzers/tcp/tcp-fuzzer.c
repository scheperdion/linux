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

/*
 *
 * extra_length: the length of the packet, gets set to 20 if less than 20 (minimum for a tcp syn packet)
 */
void tcp_create_packet(struct tcp_header * tcp_header, size_t length) {
	struct pseudo_header psh;
	tcp_header->source_port = htons(12345);   // Source port
    tcp_header->dest_port = htons(9999);      // Destination port
    tcp_header->seq_number = htonl(0);          // Sequence number
    tcp_header->ack_number = htonl(0);             // Acknowledgment number
    tcp_header->data_offset = (5 << 4);                // Data offset (no options)
    tcp_header->flags = 0x02; // SYN
    tcp_header->window_size = htons(5840);    // Window size
    tcp_header->checksum = 0;               // Initial checksum
    tcp_header->urgent_pointer = 0;             // Urgent pointer

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

void initialize_tcp_server() {
	int sock;
	struct lkl_sockaddr_in address;
	address.sin_family = LKL_AF_INET;
	address.sin_addr.lkl_s_addr = 0x0100007f;  // Accept connections from any IP address
	address.sin_port = htons(9999);

	sock = lkl_sys_socket(LKL_AF_INET, LKL_SOCK_STREAM, 0);
	lkl_sys_bind(sock, (struct lkl_sockaddr *)&address, sizeof(address));
	lkl_sys_listen(sock, 3);
}

void tcp_function(unsigned char* packet, size_t length) {
    struct lkl_sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;  // IPv4
    server_addr.sin_addr.lkl_s_addr = 0x0100007f;
    server_addr.sin_port = htons(1111);

    int clientsock = lkl_sys_socket(LKL_AF_INET, LKL_SOCK_RAW, LKL_IPPROTO_TCP); // IPPROTO_RAW is raw ip
	if (clientsock < 0) {
		printf("socket error (%s)\n", lkl_strerror(clientsock));
	}

	tcp_create_packet((struct tcp_header *)packet, length);
	int ret = lkl_sys_sendto(clientsock, packet, length < 20 ? 20 : length, 0,
			 (struct lkl_sockaddr *)&server_addr,
			 sizeof(server_addr)
	);
	if (ret < 0) {
		printf("sendto error (%s)\n", lkl_strerror(ret));
	}

	char recv_packet[1024];
	memset(recv_packet, 0, 1024);
	int errors = 0;
	while(errors < 1) {
		struct lkl_pollfd pfd;
		pfd.fd = clientsock;
		pfd.events = LKL_POLLIN;
		pfd.revents = 0;
		ret = lkl_sys_poll(&pfd, 1, 1);
		if (ret < 0) {
			printf("poll error (%s)\n", lkl_strerror(ret));
		}

		memset(recv_packet, 0, 100);
		ret = lkl_sys_recv(clientsock, recv_packet, sizeof(recv_packet), LKL_MSG_DONTWAIT);
		if (ret < 0) {
			printf("recv error (%s)\n", lkl_strerror(ret));
			errors++;
		} else {
			printf("recv bytes: %d\n", ret);
		}
	}
    //pthread_join(my_thread, NULL);
}

static int initialize_lkl(void)
{

	int ret = lkl_init(&lkl_host_ops);

	if (ret) {
		printf("lkl_init failed\n");
		return -1;
	}

	ret = lkl_start_kernel("mem=50M kasan.fault=panic");
	if (ret) {
		printf("lkl_start_kernel failed\n");
		lkl_cleanup();
		return -1;
	}

	lkl_if_up(1); // stolen from if_up test?
	initialize_tcp_server();
	return 0;
}

void flush_coverage(void)
{
	__llvm_profile_write_file();
	lkl_sys_halt();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	initialize_lkl();
	__llvm_profile_initialize_file();
	atexit(flush_coverage);

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	static int iter;
	uint8_t data[60] = {0};

	if (Size > sizeof(data))
		Size = sizeof(data);

	memcpy(data, Data, Size);
	tcp_function(data, Size < 20 ? 20 : Size);
	iter++;
	if (iter > 1000) {
		flush_coverage();
		iter = 0;
	}
	return 0;
}

//int main(int argc, char **argv) {
//	initialize_lkl();
//	unsigned char packet[60];
//	memset(packet, 0x00, 60);
//	size_t length = 60;
//	tcp_function(packet, length);
//	lkl_sys_halt();
//}
