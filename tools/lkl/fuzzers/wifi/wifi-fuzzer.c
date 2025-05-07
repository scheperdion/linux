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
void (*target)(void *wlc, void *p); // (struct brcms_c_info *wlc, struct sk_buff *p)
//void * (*packet_to_skb)(uint8_t *packet, size_t size);
int (*brcms_bcma_probe)(void* dev);  // (struct bcma_device *pdev)

void set_addresses() {
	void (*src_ptr) = &lkl_init;
	int source_offset = 0x0000000050ade0; // nm tools/lkl/fuzzers/wifi/wifi-fuzzer | grep lkl_init
	int target_offset = 0x00000000c0e8e0; // nm tools/lkl/fuzzers/wifi/wifi-fuzzer | grep brcms_c_recv
	//int packet_to_skb_offset = 0x00000000c0f280; // nm tools/lkl/fuzzers/wifi/wifi-fuzzer | grep packet_to_skb
	int brcms_bcma_probe_offset = 0x00000000bf03f0; // nm tools/lkl/fuzzers/wifi/wifi-fuzzer | grep brcms_bcma_probe
	target = src_ptr - source_offset + target_offset;
	//packet_to_skb = src_ptr - source_offset + packet_to_skb_offset;
	brcms_bcma_probe = src_ptr - source_offset + brcms_bcma_probe_offset;
}

/**
* struct brcms_c_info *wlc
* static int brcms_bcma_probe(struct bcma_device *pdev)
tools/lkl/fuzzers/wifi/wifi-fuzzer tools/lkl/fuzzers/wifi/seeds -max_len=65530 -rss_limit_mb=4096
*/

void donothing() {
	return;
}


static void fuzz_wifi(const uint8_t *data, size_t size) {
	char parsed[6 + size];
	char wlc_data[4096] = { 0 };
	for (int i = 0; i < 1024; i++) {((int*) wlc_data)[i] = i;}

	// device in dev_driver_string?
	long *b = (long*) wlc_data + 0xf;
	*b = (long) ((long*)&wlc_data + 0x10);

	// set_dev_info ?
	long *c = (long*) wlc_data + 0x2f;
	*c = (long) ((long*)&wlc_data + 0x30);

	// set_dev_info ?
	long *d = (long*) wlc_data + 0x30;
	*d = (long) "hello world";

	// set BCMA_MANUF_BCM and BCMA_CORE_80211
	long *e = (long*) wlc_data + 0x1;
	*e = (long) 0x081204bf;

	// fix set_dev_info again
	long *f = (long*) wlc_data + 0xc;
	*f = (long) "654321";

	// fix set_dev_info again
	long *g = (long*) wlc_data + 0x10;
	*g = (long) "0987";

	// set_dev_info ?
	long *h = (long*) wlc_data;
	*h = (long) ((long*)&wlc_data + 64);
	/*
[#5] 0x555555d6891a → dev_driver_string(dev=0x7fffffffd070)
[#6] 0x555555d6891a → __dev_printk(level=<optimized out>, dev=0x7fffffffd070, vaf=0x7fffffffcf60)
[#7] 0x5555560e78c7 → _dev_info(dev=0x7fffffffd070, fmt=0x555556470f20 <str> "mfg %x core %x rev %d class %d irq %d\n")
[#8] 0x55555614430f → brcms_bcma_probe(pdev=0x7fffffffd060)
[#9] 0x555555a3082b → fuzz_wifi

	brcms_bcma_probe+200
	brcms_bcma_probe+0x0ef
* */

	brcms_bcma_probe(wlc_data);

	memcpy(parsed+6, data, size);
	//target(wlc_data, packet_to_skb(data, size));
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
