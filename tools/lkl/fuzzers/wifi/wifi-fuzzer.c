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

#include "wifi-fuzzer.h"
void (*target)(void *wlc, void *p);
void * (*packet_to_skb)(uint8_t *packet, size_t size);

void set_addresses() {
	void (*src_ptr) = &lkl_init;
	int source_offset = 0x00000000494d30; // nm tools/lkl/fuzzers/wifi/wifi-fuzzer | grep lkl_init
	int target_offset = 0x00000000c4da90; // nm tools/lkl/fuzzers/wifi/wifi-fuzzer | grep brcms_c_recv
	int packet_to_skb_offset = 0x00000000c4e430; // nm tools/lkl/fuzzers/wifi/wifi-fuzzer | grep packet_to_skb
	target = src_ptr - source_offset + target_offset;
	packet_to_skb = src_ptr - source_offset + packet_to_skb_offset;
}

void donothing() {
	return;
}


static void fuzz_wifi(const uint8_t *data, size_t size) {
	char parsed[6 + size];
	char wlc_data[512] = { 0 };
	for (int i = 0; i < 512; i++) {wlc_data[i] = i;}

	// wlc_hw
	long *a = (long*) (wlc_data + 0x10);
	*a = (long) ((char*)&wlc_data + 0x18);

	// core1
	long *b = (long*) (wlc_data + 0x68);
	*b = (long) ((char*)&wlc_data + 0x70);

	// first value
	long *c = (long*) (wlc_data);
	*c = (long) ((char*)&wlc_data + 0x8);

	// core2
	long *d = (long*) (wlc_data + 0x80);
	*d = (long) ((char*)&wlc_data + 0x88);

	// second value
	long *e = (long*) (wlc_data + 0x88);
	*e = (long) ((char*)&wlc_data + 0x90);

	// core3
	long *f = (long*) (wlc_data + 0x38);
	*f = (long) ((char*)&wlc_data + 0x40);

	// third value
	long *g = (long*) (wlc_data + 0xa0);
	*g = (long) ((char*)&wlc_data + 0xa8);

	// fourth value (call r14??)
	long *h = (long*) (wlc_data + 0xb8);
	*h = (long) &donothing;

	// fourth value
	long *i = (long*) (wlc_data + 0x98);
	*i = (long) ((char*)&wlc_data + 0x100);

	// wlc_phy pih #1
	long *j = (long*) (wlc_data + 0x28 + 0x100);
	*j = (long) ((char*)&wlc_data + 0x30);

	// wlc_phy pih #2
	long *k = (long*) (wlc_data + 0x50);
	*k = (long) ((char*)&wlc_data + 0x58);

	memcpy(parsed+6, data, size);
	target(wlc_data, packet_to_skb(data, size));
}
static int initialize_lkl(void)
{
	int ret = lkl_init(&lkl_host_ops);
	if (ret) {
		printf("lkl_init failed\n");
		return -1;
	}

	ret = lkl_start_kernel("mem=4096M kasan.fault=panic");
	if (ret) {
		printf("lkl_start_kernel failed\n");
		lkl_cleanup();
		return -1;
	}
	set_addresses();
	return 0;
}



void flush_coverage(void)
{
	__llvm_profile_write_file();
}

void end_fuzzing(void) {
	flush_coverage();
	lkl_sys_halt();
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
	uint8_t data[1024] = {0};

	if (Size > 1024)
		Size = 1024;

	memcpy(data, Data, Size);
	fuzz_wifi(data, Size);
	iter++;
	if (iter > 1000) {
		flush_coverage();
		iter = 0;
	}
	return 0;
}
